<?php

namespace JeffersonGoncalves\SsrfGuard;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\SsrfGuard\Exceptions\BlockedHostException;
use JeffersonGoncalves\SsrfGuard\Exceptions\ResponseTooLargeException;

/**
 * Guards outbound HTTP requests against SSRF (Server-Side Request Forgery).
 *
 * The core primitive is resolveEntries(): for a plain http(s) URL whose host
 * resolves ONLY to public IP addresses it returns a curl CURLOPT_RESOLVE entry
 * (`host:port:ip`) pinning the host to the validated IP. Pinning closes the
 * DNS-rebinding (TOCTOU) window: without it the host would be resolved once for
 * validation and again at connect time, letting an attacker-controlled domain
 * flip to an internal IP between the two lookups.
 *
 * safeRequest()/safeGet() take this one step further: curl's own redirect
 * following is disabled and every redirect hop is followed manually so that
 * EACH hop is re-resolved, re-validated and re-pinned. A public host that 302s
 * to 169.254.169.254/localhost is therefore still blocked — curl never resolves
 * a redirect target on its own.
 */
class SsrfGuard
{
    /**
     * For a plain http(s) URL whose host resolves only to public IPs, return a
     * curl CURLOPT_RESOLVE entry (`host:port:ip`) pinning the host to the
     * validated IP. Returns null for non-http(s) URLs, unresolvable hosts, or
     * any host pointing at a private/reserved/loopback/link-local range
     * (deny-by-default).
     *
     * Both A (IPv4) and AAAA (IPv6) records are checked; if ANY resolved
     * address is non-public the whole URL is rejected.
     *
     * @return list<string>|null
     */
    public function resolveEntries(string $url): ?array
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);

        if (! in_array($scheme, $this->allowedSchemes(), true)) {
            return null;
        }

        // parse_url keeps IPv6 literals bracketed (host === "[::1]"). Strip the
        // brackets BEFORE any filter_var(... FILTER_VALIDATE_IP) check, otherwise
        // legitimate public IPv6 literals fail the IP test and fall through to a
        // hostname lookup that can never succeed.
        $host = $parts['host'];
        $bareHost = (str_starts_with($host, '[') && str_ends_with($host, ']'))
            ? substr($host, 1, -1)
            : $host;

        // Defence in depth against parse_url()/curl divergence: reject any host
        // carrying characters that could make curl re-parse the authority into a
        // different target than the one validated here (userinfo "@", path or
        // authority delimiters "/", "\\", "?", "#", whitespace and control
        // bytes). Combined with rebuildUrl() — which strips userinfo before the
        // request is sent — this guarantees curl connects to exactly the host
        // pinned by CURLOPT_RESOLVE.
        if (! $this->isValidHostSyntax($bareHost)) {
            return null;
        }

        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        if (filter_var($bareHost, FILTER_VALIDATE_IP)) {
            $ips = [$bareHost];
        } else {
            $ips = gethostbynamel($bareHost) ?: [];

            foreach (@dns_get_record($bareHost, DNS_AAAA) ?: [] as $record) {
                if (isset($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        if ($ips === []) {
            return null;
        }

        if (! $this->allowPrivate()) {
            foreach ($ips as $ip) {
                if (! $this->isPublicIp($ip)) {
                    return null;
                }
            }
        }

        // Pin to the first validated IP. CURLOPT_RESOLVE uses a
        // `HOST:PORT:ADDRESS` syntax in which IPv6 literals MUST be bracketed —
        // both for the host field (when the URL itself is an IPv6 literal) and
        // for the address field. Without the brackets curl silently ignores the
        // entry, which would disable the DNS-rebinding pin for AAAA-only hosts.
        $ip = $ips[0];
        $hostField = $this->isIpv6($bareHost) ? "[{$bareHost}]" : $bareHost;
        $ipField = $this->isIpv6($ip) ? "[{$ip}]" : $ip;

        return ["{$hostField}:{$port}:{$ipField}"];
    }

    /**
     * Strict syntax gate for the (already de-bracketed) host extracted by
     * parse_url(). Only the byte set valid for a hostname or a bare IP literal
     * is accepted; everything else is rejected so curl can never re-parse the
     * authority into a different connect target.
     */
    protected function isValidHostSyntax(string $host): bool
    {
        return $host !== '' && preg_match('/^[A-Za-z0-9._:\-]+$/', $host) === 1;
    }

    protected function isIpv6(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * True when the URL is a plain http(s) URL whose host resolves exclusively
     * to public IP addresses.
     */
    public function isPublicUrl(string $url): bool
    {
        return $this->resolveEntries($url) !== null;
    }

    /**
     * Decide whether a single resolved IP address is a public, routable address
     * safe to connect to.
     *
     * This is intentionally stricter than PHP's filter flags alone:
     *
     *  - IPv4-mapped/compatible/NAT64 IPv6 literals (e.g. `::ffff:127.0.0.1`,
     *    `::ffff:169.254.169.254`, `64:ff9b::7f00:1`) wrap an IPv4 address that
     *    PHP's NO_PRIV_RANGE|NO_RES_RANGE flags evaluate as "public". They are
     *    pure obfuscation vectors, so any IPv6 literal that embeds an IPv4
     *    address is rejected outright.
     *  - An explicit CIDR deny-list closes ranges the PHP flags miss entirely:
     *    CGNAT, IETF protocol assignments, benchmarking ranges, IPv6 ULA/
     *    link-local, loopback and the unspecified address.
     */
    public function isPublicIp(string $ip): bool
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            return false;
        }

        // IPv6 literal (16 bytes): reject anything that wraps an IPv4 address.
        if (strlen($packed) === 16 && $this->wrapsIpv4($packed)) {
            return false;
        }

        // Cheap PHP-filter gate for the bulk of private/reserved ranges.
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }

        // Explicit deny-list for ranges PHP's flags do not cover.
        foreach ($this->deniedCidrs() as $cidr) {
            if ($this->ipInCidr($packed, $cidr)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Perform a GET request that is safe against SSRF. Thin wrapper over
     * safeRequest() for the common case.
     *
     * @param  array<string, mixed>  $options  extra Guzzle/Http options, merged UNDER the safe defaults
     *
     * @throws BlockedHostException
     */
    public function safeGet(string $url, array $options = []): Response
    {
        return $this->safeRequest('GET', $url, $options);
    }

    /**
     * Perform an arbitrary-method request (GET/POST/PUT/PATCH/DELETE/HEAD) that
     * is safe against SSRF.
     *
     * The connection is pinned to the validated public IP (CURLOPT_RESOLVE) and
     * curl's own redirect following is disabled. Redirects are followed manually
     * so EACH hop is independently parsed, resolved, validated and re-pinned —
     * curl never resolves a redirect target itself, closing the DNS-rebinding
     * window on every hop.
     *
     * Throws BlockedHostException when the URL — or any redirect hop reached
     * while following one — is not public, or when the redirect limit is hit.
     *
     * @param  array<string, mixed>  $options  extra Guzzle/Http options, merged UNDER the safe defaults
     *
     * @throws BlockedHostException
     */
    public function safeRequest(string $method, string $url, array $options = []): Response
    {
        $method = strtoupper($method);
        $currentUrl = $url;
        $maxRedirects = $this->maxRedirects();

        for ($hop = 0; ; $hop++) {
            // Re-resolve, re-validate and re-pin THIS host on every hop.
            $resolve = $this->resolveEntries($currentUrl);

            if ($resolve === null) {
                throw $hop === 0
                    ? BlockedHostException::forUrl($url)
                    : BlockedHostException::forRedirect($currentUrl);
            }

            // Send a URL rebuilt from the validated parse_url() components, with
            // userinfo and fragment stripped, so curl cannot re-parse a raw,
            // ambiguous authority into a host other than the one pinned above.
            $safeUrl = $this->rebuildUrl($currentUrl);

            if ($safeUrl === null) {
                throw $hop === 0
                    ? BlockedHostException::forUrl($url)
                    : BlockedHostException::forRedirect($currentUrl);
            }

            $response = Http::timeout($this->timeout())
                ->withOptions($this->buildOptions($resolve, $options))
                ->send($method, $safeUrl);

            $this->enforceResponseSize($response, $currentUrl);

            if (! $this->isRedirectStatus($response->status())) {
                return $response;
            }

            $location = trim((string) $response->header('Location'));

            if ($location === '') {
                // A 3xx with no Location header — nothing to follow.
                return $response;
            }

            if ($hop >= $maxRedirects) {
                throw BlockedHostException::tooManyRedirects($url);
            }

            [$method, $options] = $this->adjustForRedirect($response->status(), $method, $options);
            $currentUrl = $this->resolveLocation($currentUrl, $location);
        }
    }

    /**
     * Build the per-hop Http/Guzzle options. Security-critical keys are forced
     * ON TOP of any caller-supplied options so a caller can never disable the
     * protection by passing allow_redirects/curl overrides — caller options are
     * merged UNDER these keys, not over them.
     *
     * @param  list<string>  $resolve
     * @param  array<string, mixed>  $callerOptions
     * @return array<string, mixed>
     */
    protected function buildOptions(array $resolve, array $callerOptions): array
    {
        $merged = $callerOptions;

        // Never let Guzzle auto-follow: redirects are handled manually so each
        // hop is re-resolved and re-pinned.
        $merged['allow_redirects'] = false;

        $curl = (isset($merged['curl']) && is_array($merged['curl'])) ? $merged['curl'] : [];

        // Pin the host to the validated IP and belt-and-braces disable curl's
        // own redirect following.
        $curl[CURLOPT_RESOLVE] = $resolve;
        $curl[CURLOPT_FOLLOWLOCATION] = false;

        $merged['curl'] = $curl;

        return $merged;
    }

    /**
     * Adjust method/body when following a redirect, mirroring browser/RFC
     * semantics: 303 (and 301/302 from an unsafe method) downgrade to GET and
     * drop the request body; 307/308 preserve method and body.
     *
     * @param  array<string, mixed>  $options
     * @return array{0: string, 1: array<string, mixed>}
     */
    protected function adjustForRedirect(int $status, string $method, array $options): array
    {
        $downgrade = $status === 303
            || (in_array($status, [301, 302], true) && ! in_array($method, ['GET', 'HEAD'], true));

        if ($downgrade) {
            $method = 'GET';
            unset($options['body'], $options['json'], $options['form_params'], $options['multipart']);
        }

        return [$method, $options];
    }

    /**
     * Resolve a (possibly relative) Location header against the current URL into
     * an absolute URL the next hop can re-validate.
     */
    protected function resolveLocation(string $base, string $location): string
    {
        // Absolute URL with an explicit scheme.
        if (preg_match('#^[a-z][a-z0-9+.\-]*://#i', $location) === 1) {
            return $location;
        }

        $baseParts = parse_url($base);
        $scheme = isset($baseParts['scheme']) ? strtolower($baseParts['scheme']) : 'http';

        // Scheme-relative: //host/path
        if (str_starts_with($location, '//')) {
            return $scheme.':'.$location;
        }

        $host = $baseParts['host'] ?? '';
        $authority = $scheme.'://'.$host.(isset($baseParts['port']) ? ':'.$baseParts['port'] : '');

        // Absolute path.
        if (str_starts_with($location, '/')) {
            return $authority.$location;
        }

        // Relative path — resolve against the directory of the base path.
        $basePath = $baseParts['path'] ?? '/';
        $slash = strrpos($basePath, '/');
        $dir = $slash === false ? '/' : substr($basePath, 0, $slash + 1);

        return $authority.$dir.$location;
    }

    protected function isRedirectStatus(int $status): bool
    {
        return in_array($status, [301, 302, 303, 307, 308], true);
    }

    /**
     * Rebuild an absolute http(s) URL from its validated parse_url() components,
     * dropping the userinfo (`user:pass@`) and the fragment. This strips the raw,
     * potentially ambiguous authority that curl might otherwise re-parse into a
     * different connect target than the host pinned by CURLOPT_RESOLVE (the
     * classic `http://public.com@169.254.169.254/` confusion). The IPv6 brackets
     * kept by parse_url() in the host are preserved because a URL requires them.
     * Returns null when the URL cannot be reduced to a usable scheme + host that
     * passes the same strict host-syntax gate used during validation.
     */
    protected function rebuildUrl(string $url): ?string
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);
        $host = $parts['host'];

        $bareHost = (str_starts_with($host, '[') && str_ends_with($host, ']'))
            ? substr($host, 1, -1)
            : $host;

        if (! $this->isValidHostSyntax($bareHost)) {
            return null;
        }

        $rebuilt = $scheme.'://'.$host;

        if (isset($parts['port'])) {
            $rebuilt .= ':'.$parts['port'];
        }

        $rebuilt .= $parts['path'] ?? '';

        if (isset($parts['query'])) {
            $rebuilt .= '?'.$parts['query'];
        }

        return $rebuilt;
    }

    /**
     * Abort if a response body exceeds the configured size cap. A cap of 0 (or a
     * negative value) disables the check. Both the advertised Content-Length and
     * the actual downloaded body length are tested, so neither a lying nor an
     * absent header can slip a large internal resource past the limit. Streaming
     * a big internal file back through your worker is both a DoS and an
     * exfiltration vector, hence the deny-once-exceeded posture.
     *
     * @throws ResponseTooLargeException
     */
    protected function enforceResponseSize(Response $response, string $url): void
    {
        $cap = $this->maxResponseSize();

        if ($cap <= 0) {
            return;
        }

        $contentLength = $response->header('Content-Length');

        if ($contentLength !== '' && is_numeric($contentLength) && (int) $contentLength > $cap) {
            throw ResponseTooLargeException::forUrl($url, $cap);
        }

        if (strlen($response->body()) > $cap) {
            throw ResponseTooLargeException::forUrl($url, $cap);
        }
    }

    /**
     * Does a 16-byte packed IPv6 address embed an IPv4 address (mapped,
     * compatible or NAT64)? Such literals are obfuscation vectors and are
     * rejected; the bare `::` and `::1` are left to the explicit CIDR deny-list.
     */
    protected function wrapsIpv4(string $packed): bool
    {
        // IPv4-mapped ::ffff:0:0/96
        if (substr($packed, 0, 10) === str_repeat("\x00", 10) && substr($packed, 10, 2) === "\xff\xff") {
            return true;
        }

        // NAT64 64:ff9b::/96
        if (substr($packed, 0, 12) === "\x00\x64\xff\x9b".str_repeat("\x00", 8)) {
            return true;
        }

        // IPv4-compatible ::/96 (deprecated): first 12 bytes zero, last 4 a real
        // IPv4 address. Exclude :: (0.0.0.0) and ::1 (loopback).
        if (substr($packed, 0, 12) === str_repeat("\x00", 12)) {
            $last4 = substr($packed, 12, 4);

            if ($last4 !== "\x00\x00\x00\x00" && $last4 !== "\x00\x00\x00\x01") {
                return true;
            }
        }

        return false;
    }

    /**
     * Explicit CIDR deny-list for ranges PHP's FILTER_FLAG_* do not cover.
     *
     * @return list<string>
     */
    protected function deniedCidrs(): array
    {
        return [
            // IPv4
            '0.0.0.0/8',        // "this" network
            '100.64.0.0/10',    // CGNAT (RFC 6598)
            '169.254.0.0/16',   // link-local incl. cloud metadata 169.254.169.254
            '192.0.0.0/24',     // IETF protocol assignments (RFC 6890)
            '198.18.0.0/15',    // benchmarking (RFC 2544)
            // IPv6
            '::/128',           // unspecified
            '::1/128',          // loopback
            'fc00::/7',         // unique local address
            'fe80::/10',        // link-local
        ];
    }

    /**
     * Test a packed IP (4 or 16 bytes from inet_pton) against a CIDR string,
     * for both address families.
     */
    protected function ipInCidr(string $packed, string $cidr): bool
    {
        [$subnet, $bitsStr] = explode('/', $cidr);
        $subnetPacked = @inet_pton($subnet);

        if ($subnetPacked === false || strlen($subnetPacked) !== strlen($packed)) {
            return false;
        }

        $bits = (int) $bitsStr;
        $wholeBytes = intdiv($bits, 8);
        $remainder = $bits % 8;

        if ($wholeBytes > 0 && substr($packed, 0, $wholeBytes) !== substr($subnetPacked, 0, $wholeBytes)) {
            return false;
        }

        if ($remainder !== 0) {
            $mask = chr((0xFF << (8 - $remainder)) & 0xFF);

            if ((substr($packed, $wholeBytes, 1) & $mask) !== (substr($subnetPacked, $wholeBytes, 1) & $mask)) {
                return false;
            }
        }

        return true;
    }

    protected function timeout(): int
    {
        return (int) config('ssrf-guard.timeout', 8);
    }

    protected function maxRedirects(): int
    {
        return (int) config('ssrf-guard.max_redirects', 5);
    }

    protected function maxResponseSize(): int
    {
        return (int) config('ssrf-guard.max_response_size', 10 * 1024 * 1024);
    }

    /**
     * @return array<int, string>
     */
    protected function allowedSchemes(): array
    {
        /** @var array<int, string> $schemes */
        $schemes = config('ssrf-guard.allowed_schemes', ['http', 'https']);

        return $schemes;
    }

    protected function allowPrivate(): bool
    {
        return (bool) config('ssrf-guard.allow_private', false);
    }
}
