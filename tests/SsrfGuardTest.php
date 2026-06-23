<?php

use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\SsrfGuard\Exceptions\BlockedHostException;
use JeffersonGoncalves\SsrfGuard\Exceptions\ResponseTooLargeException;
use JeffersonGoncalves\SsrfGuard\SsrfGuard;

/**
 * Exposes the security-critical protected helpers so the redirect/URL-rewriting
 * logic can be asserted directly instead of only through a mocked transport.
 */
class ExposedSsrfGuard extends SsrfGuard
{
    public function callRebuildUrl(string $url): ?string
    {
        return $this->rebuildUrl($url);
    }

    public function callResolveLocation(string $base, string $location): string
    {
        return $this->resolveLocation($base, $location);
    }

    /**
     * @param  array<string, mixed>  $options
     * @return array{0: string, 1: array<string, mixed>}
     */
    public function callAdjustForRedirect(int $status, string $method, array $options): array
    {
        return $this->adjustForRedirect($status, $method, $options);
    }

    /**
     * @param  list<string>  $resolve
     * @param  array<string, mixed>  $callerOptions
     * @return array<string, mixed>
     */
    public function callBuildOptions(array $resolve, array $callerOptions): array
    {
        return $this->buildOptions($resolve, $callerOptions);
    }
}

beforeEach(function () {
    $this->guard = new SsrfGuard;
    $this->exposed = new ExposedSsrfGuard;
});

it('blocks the loopback IP literal', function () {
    expect($this->guard->isPublicUrl('http://127.0.0.1'))->toBeFalse();
});

it('blocks the localhost hostname (resolves to loopback)', function () {
    expect($this->guard->isPublicUrl('http://localhost'))->toBeFalse();
});

it('blocks the cloud metadata link-local address', function () {
    expect($this->guard->isPublicUrl('http://169.254.169.254'))->toBeFalse();
});

it('blocks private RFC1918 ranges', function () {
    expect($this->guard->isPublicUrl('http://10.0.0.1'))->toBeFalse();
});

it('blocks non-http(s) schemes', function () {
    expect($this->guard->isPublicUrl('ftp://1.1.1.1'))->toBeFalse();
});

it('allows a public IP literal', function () {
    expect($this->guard->isPublicUrl('http://1.1.1.1'))->toBeTrue();
});

it('pins the validated public IP in the resolve entry', function () {
    expect($this->guard->resolveEntries('http://1.1.1.1'))->toBe(['1.1.1.1:80:1.1.1.1']);
});

it('uses port 443 in the resolve entry for https URLs', function () {
    expect($this->guard->resolveEntries('https://1.1.1.1'))->toBe(['1.1.1.1:443:1.1.1.1']);
});

it('returns null resolve entries for a private host', function () {
    expect($this->guard->resolveEntries('http://10.0.0.1'))->toBeNull();
});

it('throws BlockedHostException from safeGet for a private host', function () {
    $this->guard->safeGet('http://127.0.0.1');
})->throws(BlockedHostException::class);

it('throws BlockedHostException from safeGet for a non-http scheme', function () {
    $this->guard->safeGet('ftp://1.1.1.1');
})->throws(BlockedHostException::class);

it('blocks known SSRF bypass payloads', function (string $url) {
    expect($this->guard->isPublicUrl($url))->toBeFalse();
})->with([
    'decimal IPv4' => 'http://2130706433',
    'octal/hex IPv4' => 'http://0x7f.0.0.1',
    'wildcard 0.0.0.0' => 'http://0.0.0.0',
    'IPv6 loopback literal' => 'http://[::1]',
    'IPv4-mapped IPv6 loopback' => 'http://[::ffff:127.0.0.1]',
    'IPv4-mapped IPv6 metadata' => 'http://[::ffff:169.254.169.254]',
    'NAT64 metadata' => 'http://[64:ff9b::a9fe:a9fe]',
    'cloud metadata link-local' => 'http://169.254.169.254',
    'CGNAT range' => 'http://100.64.1.1',
    'IETF protocol assignment' => 'http://192.0.0.1',
    'benchmarking range' => 'http://198.18.0.1',
]);

it('allows a legitimate public IPv6 literal (brackets stripped before the IP check)', function () {
    // 2606:4700:4700::1111 is Cloudflare public DNS; no network lookup needed
    // for an IP literal, so this is deterministic.
    expect($this->guard->isPublicUrl('http://[2606:4700:4700::1111]'))->toBeTrue();
});

it('pins a public IPv6 literal in the resolve entry with brackets on both host and address', function () {
    // CURLOPT_RESOLVE uses HOST:PORT:ADDRESS; IPv6 literals MUST be bracketed in
    // BOTH the host and address fields or curl silently drops the entry, which
    // would disable the DNS-rebinding pin for AAAA-only hosts.
    expect($this->guard->resolveEntries('https://[2606:4700:4700::1111]'))
        ->toBe(['[2606:4700:4700::1111]:443:[2606:4700:4700::1111]']);
});

it('blocks a redirect hop that points at an internal host', function () {
    Http::fake(fn () => Http::response('', 302, ['Location' => 'http://169.254.169.254/latest/meta-data/']));

    $this->guard->safeGet('http://1.1.1.1');
})->throws(BlockedHostException::class);

it('returns the response on the safeGet success path', function () {
    Http::fake(fn () => Http::response('hello world', 200));

    $response = $this->guard->safeGet('http://1.1.1.1');

    expect($response->status())->toBe(200)
        ->and($response->body())->toBe('hello world');
});

it('aborts when the redirect limit is exceeded', function () {
    // Always redirect to another public host so the loop never blocks on the
    // host check but does trip the max-hops guard.
    Http::fake(fn () => Http::response('', 302, ['Location' => 'http://1.1.1.1/next']));

    config()->set('ssrf-guard.max_redirects', 2);

    $this->guard->safeGet('http://1.1.1.1');
})->throws(BlockedHostException::class);

it('allows callers options but cannot be overridden to disable pinning', function () {
    Http::fake(fn () => Http::response('ok', 200));

    // A caller trying to re-enable auto-redirects / drop the resolve pin must
    // not win: security-critical keys are forced over caller options.
    $response = $this->guard->safeGet('http://1.1.1.1', [
        'allow_redirects' => true,
        'curl' => [CURLOPT_RESOLVE => []],
        'headers' => ['X-Custom' => 'kept'],
    ]);

    expect($response->status())->toBe(200);

    Http::assertSent(function ($request) {
        return $request->hasHeader('X-Custom', 'kept');
    });
});

// ---------------------------------------------------------------------------
// parse_url() / curl divergence — userinfo "@" confusion
// ---------------------------------------------------------------------------

it('blocks a userinfo-confusion URL whose real host is internal', function () {
    // http://public.com@169.254.169.254/ — the authority before "@" is userinfo,
    // the REAL host is the metadata link-local address. Must be blocked.
    expect($this->guard->isPublicUrl('http://public.com@169.254.169.254/'))->toBeFalse();
});

it('blocks a userinfo-confusion URL pointing at loopback', function () {
    expect($this->guard->isPublicUrl('http://example.com@127.0.0.1/'))->toBeFalse();
});

it('strips userinfo and fragment when rebuilding the URL sent to curl', function () {
    expect($this->exposed->callRebuildUrl('http://user:pass@1.1.1.1/path?q=1#frag'))
        ->toBe('http://1.1.1.1/path?q=1');
});

it('rebuilds a bracketed IPv6 authority while dropping userinfo', function () {
    expect($this->exposed->callRebuildUrl('https://user@[2606:4700:4700::1111]:8443/x'))
        ->toBe('https://[2606:4700:4700::1111]:8443/x');
});

it('throws BlockedHostException from safeGet for a userinfo-confusion URL', function () {
    $this->guard->safeGet('http://public.com@169.254.169.254/latest/meta-data/');
})->throws(BlockedHostException::class);

// ---------------------------------------------------------------------------
// Scheme-relative redirects
// ---------------------------------------------------------------------------

it('resolves a scheme-relative redirect against the base scheme', function () {
    expect($this->exposed->callResolveLocation('https://1.1.1.1/a/b', '//evil.example/x'))
        ->toBe('https://evil.example/x');
});

it('blocks a scheme-relative redirect that points at an internal host', function () {
    Http::fake(fn () => Http::response('', 302, ['Location' => '//169.254.169.254/latest/']));

    $this->guard->safeGet('http://1.1.1.1');
})->throws(BlockedHostException::class);

// ---------------------------------------------------------------------------
// IPv4-compatible / -mapped IPv6 obfuscation
// ---------------------------------------------------------------------------

it('blocks IPv4-compatible IPv6 wrapping the metadata address', function () {
    // ::a9fe:a9fe expands to ::169.254.169.254 (IPv4-compatible, deprecated).
    expect($this->guard->isPublicUrl('http://[::a9fe:a9fe]'))->toBeFalse();
});

it('blocks IPv4-compatible IPv6 wrapping loopback', function () {
    // ::7f00:1 expands to ::127.0.0.1.
    expect($this->guard->isPublicUrl('http://[::7f00:1]'))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Case-insensitivity (uppercase scheme/host)
// ---------------------------------------------------------------------------

it('handles an uppercase scheme on an IPv4 literal', function () {
    expect($this->guard->resolveEntries('HTTP://1.1.1.1'))->toBe(['1.1.1.1:80:1.1.1.1']);
});

it('handles an uppercase scheme on an https IPv4 literal', function () {
    expect($this->guard->resolveEntries('HTTPS://1.1.1.1'))->toBe(['1.1.1.1:443:1.1.1.1']);
});

it('blocks an uppercase LOCALHOST hostname (resolves to loopback)', function () {
    expect($this->guard->isPublicUrl('http://LOCALHOST'))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Method downgrade across redirect status codes
// ---------------------------------------------------------------------------

it('downgrades the method and drops the body on a redirect', function (int $status, string $method, string $expectedMethod, bool $bodyKept) {
    [$newMethod, $options] = $this->exposed->callAdjustForRedirect($status, $method, [
        'body' => 'payload',
        'json' => ['a' => 1],
        'headers' => ['X-Keep' => '1'],
    ]);

    expect($newMethod)->toBe($expectedMethod)
        ->and(array_key_exists('body', $options))->toBe($bodyKept)
        ->and(array_key_exists('json', $options))->toBe($bodyKept)
        // Non-body options are always preserved.
        ->and($options['headers'])->toBe(['X-Keep' => '1']);
})->with([
    // 301/302 from an unsafe method downgrade to GET; from GET/HEAD they do not.
    '301 POST -> GET' => [301, 'POST', 'GET', false],
    '301 GET stays GET' => [301, 'GET', 'GET', true],
    '302 POST -> GET' => [302, 'POST', 'GET', false],
    '302 HEAD stays HEAD' => [302, 'HEAD', 'HEAD', true],
    // 303 always downgrades to GET, even from GET.
    '303 POST -> GET' => [303, 'POST', 'GET', false],
    '303 GET -> GET' => [303, 'GET', 'GET', false],
    // 307/308 preserve method and body.
    '307 POST stays POST' => [307, 'POST', 'POST', true],
    '308 POST stays POST' => [308, 'POST', 'POST', true],
    '307 PUT stays PUT' => [307, 'PUT', 'PUT', true],
]);

it('downgrades a real POST to GET across a 303 redirect', function () {
    $sent = [];
    Http::fake(function ($request) use (&$sent) {
        $sent[] = $request->method();

        return count($sent) === 1
            ? Http::response('', 303, ['Location' => 'http://1.1.1.1/after'])
            : Http::response('done', 200);
    });

    $response = $this->guard->safeRequest('POST', 'http://1.1.1.1/submit', ['body' => 'x']);

    expect($response->status())->toBe(200)
        ->and($sent)->toBe(['POST', 'GET']);
});

it('preserves a real POST across a 307 redirect', function () {
    $sent = [];
    Http::fake(function ($request) use (&$sent) {
        $sent[] = $request->method();

        return count($sent) === 1
            ? Http::response('', 307, ['Location' => 'http://1.1.1.1/after'])
            : Http::response('done', 200);
    });

    $response = $this->guard->safeRequest('POST', 'http://1.1.1.1/submit', ['body' => 'x']);

    expect($response->status())->toBe(200)
        ->and($sent)->toBe(['POST', 'POST']);
});

// ---------------------------------------------------------------------------
// CURLOPT_RESOLVE wiring (IPv4 and IPv6)
// ---------------------------------------------------------------------------

it('wires the IPv4 resolve pin and forces the security-critical curl options', function () {
    $options = $this->exposed->callBuildOptions(['1.1.1.1:80:1.1.1.1'], []);

    expect($options['allow_redirects'])->toBeFalse()
        ->and($options['curl'][CURLOPT_RESOLVE])->toBe(['1.1.1.1:80:1.1.1.1'])
        ->and($options['curl'][CURLOPT_FOLLOWLOCATION])->toBeFalse();
});

it('wires a bracketed IPv6 resolve pin', function () {
    $resolve = $this->guard->resolveEntries('https://[2606:4700:4700::1111]');
    $options = $this->exposed->callBuildOptions($resolve, []);

    expect($options['curl'][CURLOPT_RESOLVE])
        ->toBe(['[2606:4700:4700::1111]:443:[2606:4700:4700::1111]']);
});

it('forces the resolve pin over a caller attempt to clear it', function () {
    $options = $this->exposed->callBuildOptions(['1.1.1.1:80:1.1.1.1'], [
        'allow_redirects' => true,
        'curl' => [CURLOPT_RESOLVE => [], 'X-Other' => 'kept'],
    ]);

    expect($options['allow_redirects'])->toBeFalse()
        ->and($options['curl'][CURLOPT_RESOLVE])->toBe(['1.1.1.1:80:1.1.1.1'])
        ->and($options['curl']['X-Other'])->toBe('kept');
});

// ---------------------------------------------------------------------------
// Response size cap
// ---------------------------------------------------------------------------

it('throws ResponseTooLargeException when the body exceeds the cap', function () {
    config()->set('ssrf-guard.max_response_size', 5);

    Http::fake(fn () => Http::response('hello world', 200));

    $this->guard->safeGet('http://1.1.1.1');
})->throws(ResponseTooLargeException::class);

it('throws ResponseTooLargeException on a lying Content-Length header', function () {
    config()->set('ssrf-guard.max_response_size', 100);

    Http::fake(fn () => Http::response('', 200, ['Content-Length' => '999999']));

    $this->guard->safeGet('http://1.1.1.1');
})->throws(ResponseTooLargeException::class);

it('allows a body within the cap', function () {
    config()->set('ssrf-guard.max_response_size', 1024);

    Http::fake(fn () => Http::response('small body', 200));

    expect($this->guard->safeGet('http://1.1.1.1')->body())->toBe('small body');
});

it('disables the size cap when set to zero', function () {
    config()->set('ssrf-guard.max_response_size', 0);

    Http::fake(fn () => Http::response(str_repeat('x', 50_000), 200));

    expect(strlen($this->guard->safeGet('http://1.1.1.1')->body()))->toBe(50_000);
});
