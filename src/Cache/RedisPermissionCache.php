<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Cache;

use Wazobia\HeliosPermissions\Permission;
use Wazobia\HeliosPermissions\Support\Logger;
use Wazobia\HeliosPermissions\Support\SilentLogger;

/**
 * RedisPermissionCache — the production PermissionCache impl.
 *
 * Key shape (must match Helios's permission-cache.service.ts and the
 * TS / Python / Go SDKs):
 *
 *     helios:perms:{userId}:{tenantId}    →    JSON array of permission strings
 *
 * Drift here would silently break every cross-language consumer.
 *
 * Connection: caller-owned Predis client. The factory in Factory.php
 * either builds one or accepts an injection. The cache does NOT
 * manage the connection lifecycle — the caller (typically a
 * service's AppServiceProvider or DI container) is responsible for
 * disconnect().
 *
 * Invalidation patterns:
 *
 *   Invalidate(userId, tenantId)   → DEL helios:perms:{userId}:{tenantId}
 *   InvalidateTenant(tenantId)     → SCAN MATCH helios:perms:*:{tenantId} DEL
 *
 * SCAN is non-blocking; KEYS would block the Redis event loop on a
 * large keyspace.
 *
 * Error handling — best-effort, fail open:
 *
 *   - Get failures: log warn + return null (caller falls through to Helios).
 *   - Set / WriteThrough: log warn + return false. Caller decides —
 *     for the in-flight repopulate path, swallowing is fine.
 *   - Invalidate: log error + return. Stale data has no automatic
 *     recovery except TTL expiry. Operators need visibility.
 */
final class RedisPermissionCache implements PermissionCache
{
    public const KEY_PREFIX = 'helios:perms:';

    public const DEFAULT_TTL_SECONDS = 60;

    private const SCAN_BATCH_SIZE = 100;

    /** @var \Predis\ClientInterface */
    private $redis;

    private int $ttl;
    private string $keyPrefix;
    private Logger $logger;

    public function __construct(
        \Predis\ClientInterface $redis,
        ?int $ttlSeconds = null,
        ?string $keyPrefix = null,
        ?Logger $logger = null,
    ) {
        $this->redis = $redis;
        $this->ttl = $ttlSeconds ?? self::DEFAULT_TTL_SECONDS;
        $this->keyPrefix = $keyPrefix ?? self::KEY_PREFIX;
        $this->logger = $logger ?? new SilentLogger();
    }

    private function key(string $userId, string $tenantId): string
    {
        return $this->keyPrefix . $userId . ':' . $tenantId;
    }

    private function tenantPattern(string $tenantId): string
    {
        return $this->keyPrefix . '*:' . $tenantId;
    }

    public function get(string $userId, string $tenantId): ?array
    {
        try {
            $raw = $this->redis->get($this->key($userId, $tenantId));
        } catch (\Throwable $e) {
            $this->logger->warn('RedisPermissionCache.get failed; falling through to Helios', [
                'err' => $e->getMessage(),
                'userId' => $userId,
                'tenantId' => $tenantId,
            ]);
            return null;
        }
        if ($raw === null) {
            return null;
        }
        $decoded = json_decode((string) $raw, true);
        if (!is_array($decoded)) {
            $this->logger->warn('RedisPermissionCache.get: cached value is not a valid array; treating as miss', [
                'raw' => (string) $raw,
            ]);
            return null;
        }
        return array_values(array_map('strval', $decoded));
    }

    public function set(string $userId, string $tenantId, array $perms): bool
    {
        $payload = json_encode($this->normalize($perms));
        if ($payload === false) {
            return false;
        }
        try {
            // SET NX EX <ttl>. Predis exposes set with options as an
            // associative array of options.
            $res = $this->redis->set(
                $this->key($userId, $tenantId),
                $payload,
                'EX',
                $this->ttl,
                'NX',
            );
        } catch (\Throwable $e) {
            $this->logger->warn('RedisPermissionCache.set failed; continuing without cache', [
                'err' => $e->getMessage(),
                'userId' => $userId,
                'tenantId' => $tenantId,
            ]);
            return false;
        }
        // Predis returns Status('OK') on store, null when NX failed.
        return $res !== null;
    }

    public function writeThrough(string $userId, string $tenantId, array $perms): bool
    {
        $payload = json_encode($this->normalize($perms));
        if ($payload === false) {
            return false;
        }
        try {
            $this->redis->set(
                $this->key($userId, $tenantId),
                $payload,
                'EX',
                $this->ttl,
            );
        } catch (\Throwable $e) {
            $this->logger->warn('RedisPermissionCache.writeThrough failed; continuing without cache', [
                'err' => $e->getMessage(),
                'userId' => $userId,
                'tenantId' => $tenantId,
            ]);
            return false;
        }
        return true;
    }

    public function invalidate(string $userId, string $tenantId): void
    {
        try {
            $deleted = $this->redis->del([$this->key($userId, $tenantId)]);
        } catch (\Throwable $e) {
            $this->logger->error('RedisPermissionCache.invalidate failed — cache may be stale for up to TTL seconds', [
                'err' => $e->getMessage(),
                'userId' => $userId,
                'tenantId' => $tenantId,
            ]);
            return;
        }
        $this->logger->info('RedisPermissionCache.invalidate: deleted (userId, tenantId) entry', [
            'userId' => $userId,
            'tenantId' => $tenantId,
            'deleted' => $deleted,
        ]);
    }

    public function invalidateTenant(string $tenantId): void
    {
        $pattern = $this->tenantPattern($tenantId);
        $cursor = 0;
        $totalDeleted = 0;
        try {
            // Predis scan iterator returns keys matching the pattern.
            $it = null;
            // Predis 2.x: use scan() with a closure callback to
            // receive the keys per page.
            $this->redis->scan($cursor, ['MATCH' => $pattern, 'COUNT' => self::SCAN_BATCH_SIZE], function (array $keys) use (&$totalDeleted, $tenantId) {
                if (count($keys) === 0) {
                    return;
                }
                try {
                    $n = $this->redis->del($keys);
                    $totalDeleted += (int) $n;
                } catch (\Throwable $e) {
                    $this->logger->error('RedisPermissionCache.invalidateTenant: DEL failed', [
                        'err' => $e->getMessage(),
                        'tenantId' => $tenantId,
                        'keys' => $keys,
                    ]);
                }
            });
        } catch (\Throwable $e) {
            $this->logger->error('RedisPermissionCache.invalidateTenant failed — cache may be stale for up to TTL seconds', [
                'err' => $e->getMessage(),
                'tenantId' => $tenantId,
            ]);
            return;
        }
        $this->logger->info('RedisPermissionCache.invalidateTenant: deleted all entries for tenant', [
            'tenantId' => $tenantId,
            'deleted' => $totalDeleted,
        ]);
    }

    /**
     * @param  Permission[]  $perms
     * @return list<string>
     */
    private function normalize(array $perms): array
    {
        $out = [];
        foreach ($perms as $p) {
            $out[] = $p instanceof Permission ? $p->value : (string) $p;
        }
        return $out;
    }
}
