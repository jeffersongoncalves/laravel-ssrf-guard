<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Request Timeout
    |--------------------------------------------------------------------------
    |
    | Maximum number of seconds a guarded GET request (SsrfGuard::safeGet) may
    | spend before it is aborted. Keep this low — long timeouts widen the
    | window an attacker has to tie up your worker against an internal service.
    |
    */
    'timeout' => (int) env('SSRF_GUARD_TIMEOUT', 8),

    /*
    |--------------------------------------------------------------------------
    | Maximum Redirects
    |--------------------------------------------------------------------------
    |
    | How many redirect hops safeGet()/safeRequest() will follow. Redirects are
    | followed MANUALLY: every hop is independently re-resolved, re-validated and
    | re-pinned (curl never follows a redirect itself), so a public host that
    | 302s to an internal address (e.g. 169.254.169.254 / localhost) is blocked.
    |
    */
    'max_redirects' => (int) env('SSRF_GUARD_MAX_REDIRECTS', 5),

    /*
    |--------------------------------------------------------------------------
    | Allowed Schemes
    |--------------------------------------------------------------------------
    |
    | Only URLs using one of these schemes are ever considered public. Anything
    | else (ftp://, file://, gopher://, dict://, …) is rejected outright — these
    | are classic SSRF pivot schemes and should not be added without good cause.
    |
    */
    'allowed_schemes' => ['http', 'https'],

    /*
    |--------------------------------------------------------------------------
    | Allow Private Ranges
    |--------------------------------------------------------------------------
    |
    | DANGER: when true, the deny-by-default check for private, reserved,
    | loopback and link-local IP ranges is skipped, allowing requests to
    | internal hosts. This exists ONLY for local development/testing against
    | services on your own machine. NEVER enable it in production.
    |
    */
    'allow_private' => (bool) env('SSRF_GUARD_ALLOW_PRIVATE', false),

    /*
    |--------------------------------------------------------------------------
    | Maximum Response Size
    |--------------------------------------------------------------------------
    |
    | Maximum number of bytes a guarded response body (safeGet()/safeRequest())
    | may contain before it is rejected with a ResponseTooLargeException. Both the
    | advertised Content-Length header and the actual downloaded length are
    | checked. Streaming a large internal resource back through your worker is a
    | DoS and exfiltration vector, so keep this bounded. Set to 0 to disable the
    | cap. Defaults to 10 MiB.
    |
    */
    'max_response_size' => (int) env('SSRF_GUARD_MAX_RESPONSE_SIZE', 10 * 1024 * 1024),
];
