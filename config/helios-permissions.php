<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Helios base URL
    |--------------------------------------------------------------------------
    |
    | The base URL of the Helios service. The SDK calls
    | GET {base_url}/internal/permissions/{userId}?tenantId={tenantId}
    | which is HMAC-gated.
    |
    */

    'helios_base_url' => env('HELIOS_BASE_URL'),

    /*
    |--------------------------------------------------------------------------
    | HMAC shared secret
    |--------------------------------------------------------------------------
    |
    | The shared HMAC key for Helios auth. Must match what the Helios
    | service has configured (SIGNATURE_SHARED_SECRET in Helios's env).
    |
    */

    'signature_shared_secret' => env('SIGNATURE_SHARED_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | x-source-service header
    |--------------------------------------------------------------------------
    |
    | The value of the x-source-service header. Default
    | "helios-permissions-laravel".
    |
    */

    'helios_source_service' => env('HELIOS_SOURCE_SERVICE', 'helios-permissions-laravel'),

    /*
    |--------------------------------------------------------------------------
    | Shared permission cache Redis URL
    |--------------------------------------------------------------------------
    |
    | Helios writes the new perm array to this Redis after every role
    | change. The SDK reads from it. Same instance for everyone —
    | PERMISSION_REDIS_URL is the contract.
    |
    */

    'redis_url' => env('PERMISSION_REDIS_URL'),

    /*
    |--------------------------------------------------------------------------
    | Cache TTL
    |--------------------------------------------------------------------------
    |
    | The safety net when invalidation fails. Default 60 seconds.
    |
    */

    'cache_ttl_seconds' => (int) env('CACHE_TTL_SECONDS', 60),

    /*
    |--------------------------------------------------------------------------
    | Stale on error
    |--------------------------------------------------------------------------
    |
    | If true (default), on Helios unreachable with a cached value,
    | return the cached value (fail-closed: allow stale, deny fresh).
    | If false, propagate the error.
    |
    */

    'stale_on_error' => filter_var(env('STALE_ON_ERROR', true), FILTER_VALIDATE_BOOLEAN),

    /*
    |--------------------------------------------------------------------------
    | Fetch timeout
    |--------------------------------------------------------------------------
    |
    | Per-request timeout to Helios. The cache is on the hot path; a
    | Helios fetch is a fallback, not a blocking operation. Default 2s.
    |
    */

    'fetch_timeout_seconds' => (float) env('HELIOS_FETCH_TIMEOUT_SECONDS', 2.0),

    /*
    |--------------------------------------------------------------------------
    | Logger
    |--------------------------------------------------------------------------
    |
    | null / "silent" → no logging. "console" → stderr. An object
    | implementing Wazobia\HeliosPermissions\Support\Logger → use that.
    |
    */

    'logger' => env('HELIOS_PERMISSIONS_LOGGER', 'silent'),

];
