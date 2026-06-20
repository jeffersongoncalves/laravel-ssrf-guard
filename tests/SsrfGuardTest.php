<?php

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
