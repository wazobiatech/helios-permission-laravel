<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions;

use Illuminate\Http\Client\Factory as HttpFactory;
use Wazobia\HeliosPermissions\Cache\PermissionCache;
use Wazobia\HeliosPermissions\Cache\RedisPermissionCache;
use Wazobia\HeliosPermissions\Support\ConsoleLogger;
use Wazobia\HeliosPermissions\Support\Logger;
use Wazobia\HeliosPermissions\Support\SilentLogger;

/**
 * Factory — the only public constructor. Wires HeliosClient +
 * RedisPermissionCache + PermissionClient and owns the Predis
 * connection lifecycle.
 *
 * Example:
 *
 *   $r = Factory::create(config('helios-permissions'));
 *   $r->client->callerHasPermission($userId, $tenantId, Permission::AthensProjectView);
 *   // $r->close() on shutdown.
 */
final class Factory
{
    /**
     * @param  array<string, mixed>  $config  see config/helios-permissions.php
     */
    public static function create(array $config): PermissionClientResult
    {
        $baseUrl = self::requiredString($config, 'helios_base_url');
        $secret = self::requiredString($config, 'signature_shared_secret');

        $sourceService = $config['helios_source_service'] ?? HeliosClient::SOURCE_SERVICE_DEFAULT;
        $ttl = (int) ($config['cache_ttl_seconds'] ?? RedisPermissionCache::DEFAULT_TTL_SECONDS);
        $staleOnError = (bool) ($config['stale_on_error'] ?? true);
        $fetchTimeout = (float) ($config['fetch_timeout_seconds'] ?? 2.0);
        $logger = self::resolveLogger($config['logger'] ?? null);

        // Cache — build or accept injection.
        $ownsRedis = false;
        /** @var \Predis\ClientInterface|null $redis */
        $redis = $config['redis'] ?? null;
        if ($redis === null) {
            $redisUrl = self::requiredString($config, 'redis_url');
            $redis = new \Predis\Client($redisUrl);
            $ownsRedis = true;
        }
        // Fail fast on misconfiguration. predis ping returns Status
        // (stringable to 'PONG' on success).
        try {
            $pong = (string) $redis->ping();
            if ($pong !== 'PONG' && $pong !== '+PONG') {
                throw new \RuntimeException('unexpected ping response: ' . $pong);
            }
        } catch (\Throwable $e) {
            if ($ownsRedis) {
                try { $redis->disconnect(); } catch (\Throwable) {}
            }
            throw new \RuntimeException(
                'helios_permissions: Redis ping failed: ' . $e->getMessage(),
                previous: $e,
            );
        }

        $cache = new RedisPermissionCache($redis, $ttl, null, $logger);

        // HeliosClient. Caller can inject an HttpFactory for tests.
        $http = $config['http_factory'] ?? null;
        $helios = new HeliosClient(
            $baseUrl,
            $secret,
            $sourceService,
            $http,
            $fetchTimeout,
        );

        $client = new PermissionClient($cache, $helios, $staleOnError, $logger);

        $closed = false;
        $close = static function () use (&$closed, $ownsRedis, $redis) {
            if ($closed) {
                return;
            }
            $closed = true;
            if ($ownsRedis) {
                try { $redis->disconnect(); } catch (\Throwable) {}
            }
        };

        return new PermissionClientResult($client, $redis, $close);
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private static function requiredString(array $config, string $key): string
    {
        $v = $config[$key] ?? null;
        if (!is_string($v) || $v === '') {
            throw new \InvalidArgumentException("helios_permissions: config['{$key}'] is required");
        }
        return $v;
    }

    private static function resolveLogger(mixed $cfg): Logger
    {
        if ($cfg instanceof Logger) {
            return $cfg;
        }
        if ($cfg === 'console' || $cfg === true) {
            return new ConsoleLogger();
        }
        if ($cfg === 'silent' || $cfg === false || $cfg === null) {
            return new SilentLogger();
        }
        return new SilentLogger();
    }
}
