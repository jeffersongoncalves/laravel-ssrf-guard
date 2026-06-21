<?php

use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\SsrfGuard\Exceptions\BlockedHostException;
use JeffersonGoncalves\SsrfGuard\SsrfGuard;

beforeEach(function () {
    $this->guard = new SsrfGuard;
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

it('pins a public IPv6 literal in the resolve entry without brackets', function () {
    expect($this->guard->resolveEntries('https://[2606:4700:4700::1111]'))
        ->toBe(['2606:4700:4700::1111:443:2606:4700:4700::1111']);
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
