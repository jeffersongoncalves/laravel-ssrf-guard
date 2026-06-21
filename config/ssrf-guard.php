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
];
