<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions;

use Closure;
use Predis\ClientInterface;

/**
 * PermissionClientResult — the value returned by Factory::create().
 *
 * The caller uses the public `client` for permission checks and
 * calls `close()` on shutdown. `redis` is exposed so the host can
 * share the connection with other modules. `helios` is exposed for
 * tests and advanced use cases.
 */
final class PermissionClientResult
{
    public function __construct(
        public readonly PermissionClientInterface $client,
        public readonly ClientInterface $redis,
        public readonly Closure $close,
    ) {
    }
}
