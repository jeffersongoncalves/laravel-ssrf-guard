<?php

namespace JeffersonGoncalves\SsrfGuard;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\SsrfGuard\Exceptions\BlockedHostException;

/**
 * Guards outbound HTTP requests against SSRF (Server-Side Request Forgery).
 *
 * The core primitive is resolveEntries(): for a plain http(s) URL whose host
 * resolves ONLY to public IP addresses it returns a curl CURLOPT_RESOLVE entry
 * (`host:port:ip`) pinning the host to the validated IP. Pinning closes the
 * DNS-rebinding (TOCTOU) window: without it the host would be resolved once for
 * validation and again at connect time, letting an attacker-controlled domain
 * flip to an internal IP between the two lookups.
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

        $host = $parts['host'];
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips = [$host];
        } else {
            $ips = gethostbynamel($host) ?: [];

            foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
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
                if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return null;
                }
            }
        }

        // Pin to the first validated IP. curl needs the bare host (no brackets).
        $bareHost = trim($host, '[]');

        return ["{$bareHost}:{$port}:{$ips[0]}"];
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
     * Perform a GET request that is safe against SSRF: the connection is pinned
     * to the validated public IP (CURLOPT_RESOLVE) and every redirect hop is
     * re-validated against the same public-IP guard.
     *
     * Throws BlockedHostException when the URL — or any redirect hop reached
     * while following one — is not public.
     *
     * @param  array<string, mixed>  $options  extra Guzzle/Http options, merged over the safe defaults
     *
     * @throws BlockedHostException
     */
    public function safeGet(string $url, array $options = []): Response
    {
        $resolve = $this->resolveEntries($url);

        if ($resolve === null) {
            throw BlockedHostException::forUrl($url);
        }

        $defaults = [
            // Follow redirects but re-validate every hop: the CURLOPT_RESOLVE
            // pin only covers the first host, so without this a public host
            // could 302 to 169.254.169.254/localhost and defeat the IP guard.
            'allow_redirects' => [
                'max' => $this->maxRedirects(),
                'strict' => true,
                'referer' => false,
                'protocols' => $this->allowedSchemes(),
                'on_redirect' => function ($request, $response, $uri): void {
                    if ($this->resolveEntries((string) $uri) === null) {
                        throw BlockedHostException::forRedirect((string) $uri);
                    }
                },
            ],
            'curl' => [CURLOPT_RESOLVE => $resolve],
        ];

        return Http::timeout($this->timeout())
            ->withOptions(array_replace_recursive($defaults, $options))
            ->get($url);
    }

    protected function timeout(): int
    {
        return (int) config('ssrf-guard.timeout', 8);
    }

    protected function maxRedirects(): int
    {
        return (int) config('ssrf-guard.max_redirects', 3);
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
