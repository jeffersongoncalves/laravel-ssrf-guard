<div class="filament-hidden">

![Laravel SSRF Guard](https://raw.githubusercontent.com/jeffersongoncalves/laravel-ssrf-guard/master/art/jeffersongoncalves-laravel-ssrf-guard.png)

</div>

# Laravel SSRF Guard

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jeffersongoncalves/laravel-ssrf-guard.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-ssrf-guard)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-ssrf-guard/run-tests.yml?branch=master&label=tests&style=flat-square)](https://github.com/jeffersongoncalves/laravel-ssrf-guard/actions?query=workflow%3Arun-tests+branch%3Amaster)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-ssrf-guard/fix-php-code-style-issues.yml?branch=master&label=code%20style&style=flat-square)](https://github.com/jeffersongoncalves/laravel-ssrf-guard/actions?query=workflow%3A"Fix+PHP+code+styling"+branch%3Amaster)
[![Total Downloads](https://img.shields.io/packagist/dt/jeffersongoncalves/laravel-ssrf-guard.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-ssrf-guard)

Whenever your application fetches a URL that came from a user — an avatar URL, a webhook target, a link preview, an imported `og:image` — it can be tricked into reaching **internal** services instead: `http://localhost`, `http://10.0.0.1`, or the cloud metadata endpoint `http://169.254.169.254`. That is **Server-Side Request Forgery (SSRF)**.

Laravel SSRF Guard makes fetching untrusted URLs safe. It:

- validates that a URL's host resolves **only** to public IP addresses, denying private, reserved, loopback and link-local ranges by default (both IPv4 `A` and IPv6 `AAAA` records);
- **pins** the connection to the validated IP via curl's `CURLOPT_RESOLVE`, closing the DNS-rebinding (TOCTOU) window where a domain flips to an internal IP between validation and connection;
- performs a safe `GET` that follows redirects but **re-validates every hop**, so a public host cannot `302` you into an internal one.

## Installation

You can install the package via composer:

```bash
composer require jeffersongoncalves/laravel-ssrf-guard
```

You can publish the config file with:

```bash
php artisan vendor:publish --tag="ssrf-guard-config"
```

This is the published config file:

```php
return [
    'timeout' => (int) env('SSRF_GUARD_TIMEOUT', 8),
    'max_redirects' => (int) env('SSRF_GUARD_MAX_REDIRECTS', 5),
    'allowed_schemes' => ['http', 'https'],
    'allow_private' => (bool) env('SSRF_GUARD_ALLOW_PRIVATE', false),
    'max_response_size' => (int) env('SSRF_GUARD_MAX_RESPONSE_SIZE', 10 * 1024 * 1024),
];
```

## Usage

Resolve the guard from the container (it is registered as a singleton) or instantiate it directly.

### Check whether a URL is safe to fetch

```php
use JeffersonGoncalves\SsrfGuard\SsrfGuard;

$guard = app(SsrfGuard::class);

$guard->isPublicUrl('https://example.com');     // true
$guard->isPublicUrl('http://127.0.0.1');        // false (loopback)
$guard->isPublicUrl('http://10.0.0.1');         // false (private)
$guard->isPublicUrl('http://169.254.169.254');  // false (link-local / metadata)
$guard->isPublicUrl('ftp://example.com');       // false (scheme not allowed)
```

Use it to validate user input before storing or fetching it:

```php
if (! app(SsrfGuard::class)->isPublicUrl($request->input('webhook_url'))) {
    abort(422, 'The URL must point to a public host.');
}
```

### Fetch a URL safely

`safeGet()` performs the pinned, redirect-re-validating request and returns a standard `Illuminate\Http\Client\Response`. It throws `JeffersonGoncalves\SsrfGuard\Exceptions\BlockedHostException` if the URL — or any redirect hop — is not public:

```php
use JeffersonGoncalves\SsrfGuard\SsrfGuard;
use JeffersonGoncalves\SsrfGuard\Exceptions\BlockedHostException;

try {
    $response = app(SsrfGuard::class)->safeGet($untrustedUrl);

    $body = $response->body();
} catch (BlockedHostException $e) {
    report($e);
    // The URL pointed at a non-public host — refuse to proxy it.
}
```

You can pass extra HTTP Client options; they are merged over the safe defaults:

```php
$response = app(SsrfGuard::class)->safeGet($url, [
    'headers' => ['Accept' => 'image/*'],
]);
```

`safeGet()`/`safeRequest()` also cap the response body at `max_response_size` (10 MiB by default), throwing `JeffersonGoncalves\SsrfGuard\Exceptions\ResponseTooLargeException` when an internal resource is larger than the cap — both the advertised `Content-Length` and the actual downloaded length are checked. Set the cap to `0` to disable it.

> [!IMPORTANT]
> `safeGet()` guarantees the **transport** is not pointed at an internal host. It does not validate the **response body**. If you re-serve fetched content from your own origin (images, HTML), still validate the `Content-Type` and sanitize/transform the body to avoid stored XSS.

### Getting the curl resolve pin

If you build your own request and just want the validated `CURLOPT_RESOLVE` entries, call `resolveEntries()` — it returns `null` for any non-public/unsupported URL:

```php
$resolve = app(SsrfGuard::class)->resolveEntries('https://example.com');
// ['example.com:443:93.184.216.34']  (or null if not public)
```

## Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `timeout` | `8` | Maximum seconds a `safeGet()` request may run. |
| `max_redirects` | `5` | How many redirect hops to follow — each one is re-validated. |
| `allowed_schemes` | `['http', 'https']` | Schemes considered valid; everything else is rejected. |
| `allow_private` | `false` | **DANGER** — when `true`, skips the private/reserved/loopback/link-local check. For local development only; never enable in production. |
| `max_response_size` | `10485760` (10 MiB) | Maximum response body size in bytes; larger responses throw `ResponseTooLargeException`. Set to `0` to disable. |

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Jèfferson Gonçalves](https://github.com/jeffersongoncalves)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
