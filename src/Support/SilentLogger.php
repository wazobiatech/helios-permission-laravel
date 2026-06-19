<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Support;

/**
 * SilentLogger — no-op Logger. The default. Useful for tests and
 * for services that don't want the SDK to log.
 */
final class SilentLogger implements Logger
{
    public function debug(string $msg, array $kv = []): void
    {
    }

    public function info(string $msg, array $kv = []): void
    {
    }

    public function warn(string $msg, array $kv = []): void
    {
    }

    public function error(string $msg, array $kv = []): void
    {
    }
}
