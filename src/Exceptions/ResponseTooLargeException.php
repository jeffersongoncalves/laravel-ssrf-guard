<?php

namespace JeffersonGoncalves\SsrfGuard\Exceptions;

use RuntimeException;

/**
 * Thrown when a guarded response body exceeds the configured maximum size.
 * Streaming a large internal resource back through your worker is both a
 * denial-of-service and a data-exfiltration risk, so the download is aborted
 * once the cap is passed. The message includes the offending URL and the cap so
 * the block is auditable.
 */
class ResponseTooLargeException extends RuntimeException
{
    public static function forUrl(string $url, int $maxBytes): self
    {
        return new self("SSRF guard aborted a response exceeding {$maxBytes} bytes: {$url}");
    }
}
