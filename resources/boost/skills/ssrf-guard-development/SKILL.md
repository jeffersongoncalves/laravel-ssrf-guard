---
name: ssrf-guard-development
description: Development guide for laravel-ssrf-guard, a package that protects outbound HTTP requests from SSRF by validating that a URL resolves only to public IPs, pinning the connection to the validated IP to close the DNS-rebinding window, and re-validating every redirect hop.
---

# SSRF Guard Development Skill

## When to use this skill

- When developing or extending the laravel-ssrf-guard package
- When modifying the public-IP validation logic (the SSRF guard itself)
- When changing how the connection is pinned (CURLOPT_RESOLVE)
- When adjusting redirect handling / re-validation
- When writing tests for SSRF protection
- When reviewing any change that could weaken the guard (security-critical)

## What is SSRF?

Server-Side Request Forgery: an attacker supplies a URL that your server fetches,
and uses it to reach resources the attacker cannot reach directly — internal
admin panels, databases, or the cloud metadata endpoint
(`http://169.254.169.254/latest/meta-data/`, which can leak IAM credentials).

Naive defenses fail in two classic ways:

1. **Blocklist of hostnames** — `localhost` has countless aliases and a host can
   simply point a public domain at `127.0.0.1` / `10.0.0.1`.
2. **Validate-then-fetch (TOCTOU)** — you resolve the host, see a public IP,
   then fetch; between those two lookups the attacker's DNS flips to an internal
   IP (DNS rebinding). The validation is meaningless without pinning.

This package addresses both: it validates **every resolved IP** (A + AAAA) and
**pins** the connection to the validated IP so the second lookup cannot differ.

## Setup

### Requirements
- PHP 8.2+
- Laravel 11, 12, or 13
- `spatie/laravel-package-tools` ^1.14
- ext-curl (the pin relies on curl's `CURLOPT_RESOLVE`)

### Installation

```bash
composer require jeffersongoncalves/laravel-ssrf-guard
```

## Package Structure

```
src/
  SsrfGuardServiceProvider.php          # name('laravel-ssrf-guard')->hasConfigFile('ssrf-guard'); binds SsrfGuard singleton
  SsrfGuard.php                         # The service: resolveEntries(), isPublicUrl(), safeGet()
  Exceptions/
    BlockedHostException.php            # Thrown by safeGet() for a non-public URL or redirect hop
config/
  ssrf-guard.php                        # timeout, max_redirects, allowed_schemes, allow_private
tests/
  SsrfGuardTest.php                     # Pest tests (use IP literals to stay deterministic)
  TestCase.php
  Pest.php
```

## The Public API

### `resolveEntries(string $url): ?array`

The core primitive. Returns a curl `CURLOPT_RESOLVE` entry list
(`["host:port:ip"]`) when the URL is a plain http(s) URL whose host resolves
**only** to public IPs; otherwise `null`. Steps:

1. `parse_url`; require a `scheme` and `host`.
2. Scheme must be in `allowed_schemes` (default `http`/`https`).
3. If the host is an IP literal, use it directly; otherwise resolve **both**
   IPv4 (`gethostbynamel`) and IPv6 (`dns_get_record(..., DNS_AAAA)`).
4. If nothing resolved → `null`.
5. Unless `allow_private` is true, **every** resolved IP must pass
   `FILTER_VALIDATE_IP` with `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`.
   A single private/reserved/loopback/link-local address rejects the whole URL.
6. Pin to the first validated IP, returning `["{bareHost}:{port}:{ip}"]`. The
   host is stripped of `[]` because curl wants the bare host for IPv6.

### `isPublicUrl(string $url): bool`

Thin wrapper: `resolveEntries($url) !== null`. Use it to validate user-supplied
URLs before storing or fetching them.

### `safeGet(string $url, array $options = []): Response`

1. `resolveEntries($url)`; throw `BlockedHostException::forUrl()` if `null`.
2. Build Guzzle options:
   - `allow_redirects` with `max = max_redirects`, and an `on_redirect` callback
     that calls `resolveEntries()` on every hop and throws
     `BlockedHostException::forRedirect()` if a hop is not public.
   - `curl => [CURLOPT_RESOLVE => $resolve]` to pin the first host.
3. Caller `$options` are merged over the defaults via `array_replace_recursive`.
4. `Http::timeout(...)->withOptions(...)->get($url)`.

> The redirect re-validation is essential: the `CURLOPT_RESOLVE` pin only covers
> the **first** host. Without `on_redirect`, a public host could `302` to
> `http://169.254.169.254` and defeat the guard.

## Configuration

```php
// config/ssrf-guard.php
'timeout' => 8,                       // seconds per safeGet request
'max_redirects' => 3,                 // hops followed, each re-validated
'allowed_schemes' => ['http','https'],
'allow_private' => false,             // DANGER: true disables the private-range guard (local dev only)
```

`allow_private` is the only knob that can weaken the guard. It exists for local
testing against services on your own machine and must never be true in
production. There is intentionally **no** allowlist of specific private hosts —
deny-by-default is the whole point.

## Testing Patterns

Use **IP literals** wherever possible so tests do not depend on live DNS and
stay deterministic in CI. Hostname cases (`localhost`) rely on resolution and
should be limited to ones that reliably resolve to a loopback/private address.

```php
use JeffersonGoncalves\SsrfGuard\SsrfGuard;
use JeffersonGoncalves\SsrfGuard\Exceptions\BlockedHostException;

beforeEach(fn () => $this->guard = new SsrfGuard);

it('blocks loopback / private / link-local', function () {
    expect($this->guard->isPublicUrl('http://127.0.0.1'))->toBeFalse();
    expect($this->guard->isPublicUrl('http://10.0.0.1'))->toBeFalse();
    expect($this->guard->isPublicUrl('http://169.254.169.254'))->toBeFalse();
});

it('blocks non-http schemes', function () {
    expect($this->guard->isPublicUrl('ftp://1.1.1.1'))->toBeFalse();
});

it('allows and pins a public IP', function () {
    expect($this->guard->resolveEntries('http://1.1.1.1'))->toBe(['1.1.1.1:80:1.1.1.1']);
});

it('throws on safeGet to a private host', function () {
    $this->guard->safeGet('http://127.0.0.1');
})->throws(BlockedHostException::class);
```

`safeGet()` to a private host throws **before** any HTTP call (the guard runs
first), so those tests need no `Http::fake()` and make no network requests.

### Running Tests

```bash
vendor/bin/pest            # all tests
vendor/bin/pest --coverage # with coverage
vendor/bin/phpstan analyse # static analysis (level 5)
vendor/bin/pint            # code style
```

## Rules for Changing the Guard (read before editing src/)

- **Never** weaken `resolveEntries()`. Keep both `FILTER_FLAG_NO_PRIV_RANGE`
  and `FILTER_FLAG_NO_RES_RANGE`, and keep checking **all** resolved IPs.
- **Never** drop the IPv6 (`AAAA`) lookup — an attacker can hide an internal
  address behind an IPv6 record.
- **Never** remove the `CURLOPT_RESOLVE` pin or the `on_redirect` re-validation;
  each closes a distinct attack (rebinding / redirect pivot).
- Adding a scheme to `allowed_schemes` is a security decision — `file://`,
  `gopher://`, `dict://` etc. are SSRF pivots and must stay out.
- Any new fetch helper must route through `resolveEntries()` and pin the IP the
  same way `safeGet()` does.
- Treat the response body as untrusted: validate `Content-Type` and sanitize
  before re-serving from your own origin (the guard secures transport, not content).
```
