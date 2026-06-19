<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Events;

use RuntimeException;
use Throwable;

/**
 * HeliosUnreachableError — thrown by HeliosClient when the upstream
 * call fails for any reason: HTTP non-2xx, network error, body parse
 * error, or HMAC verification failure on the response side (we don't
 * sign responses, so this should not happen).
 *
 * StatusCode is the HTTP status, or 0 if the failure was network-
 * level (timeout, DNS, connection refused).
 *
 * The PermissionClient (cache layer) catches this and treats it as
 * "stale" — returns the cached value if present.
 */
final class HeliosUnreachableError extends RuntimeException
{
    public function __construct(
        public readonly int $statusCode,
        public readonly string $reason,
        ?Throwable $previous = null,
    ) {
        $msg = sprintf(
            'helios unreachable (status=%d, reason=%s)',
            $statusCode,
            $reason,
        );
        if ($previous !== null) {
            $msg .= ': ' . $previous->getMessage();
        }
        parent::__construct($msg, 0, $previous);
    }
}
