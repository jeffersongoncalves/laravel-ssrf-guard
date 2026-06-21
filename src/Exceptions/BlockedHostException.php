<?php

namespace JeffersonGoncalves\SsrfGuard\Exceptions;

use RuntimeException;

/**
 * Thrown when a URL — or any redirect hop reached while following one — points
 * at a host that does not resolve exclusively to public IP addresses. The
 * message intentionally includes the offending URL so the block is auditable.
 */
class BlockedHostException extends RuntimeException
{
    public static function forUrl(string $url): self
    {
        return new self("SSRF guard blocked a request to a non-public host: {$url}");
    }

    public static function forRedirect(string $url): self
    {
        return new self("SSRF guard blocked a redirect to a non-public host: {$url}");
    }

    public static function tooManyRedirects(string $url): self
    {
        return new self("SSRF guard aborted a request that exceeded the redirect limit: {$url}");
    }
}
