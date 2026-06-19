<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Support;

/**
 * Logger — the minimal logging surface the SDK needs. The host
 * service injects its logger; the SDK does not log to stdout by
 * default (a misbehaving cache layer should not pollute the host's
 * logs).
 *
 * The methods accept $kv as an associative array of structured
 * key-value pairs. Production services should map this onto their
 * structured-logging library of choice (Monolog, Sentry, etc.).
 */
interface Logger
{
    /**
     * @param  array<string, mixed>  $kv
     */
    public function debug(string $msg, array $kv = []): void;

    /**
     * @param  array<string, mixed>  $kv
     */
    public function info(string $msg, array $kv = []): void;

    /**
     * @param  array<string, mixed>  $kv
     */
    public function warn(string $msg, array $kv = []): void;

    /**
     * @param  array<string, mixed>  $kv
     */
    public function error(string $msg, array $kv = []): void;
}
