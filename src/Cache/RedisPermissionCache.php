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
 * TTL policy (no expiry by default):
 *
 *   The cache is the primary read path for callerHasPermission. We
 *   target a 90-98% hit rate, which means entries must outlive the
 *   request burst. Every entry is invalidated explicitly at the
 *   mutation site — Helios calls WriteThrough / Invalidate after
 *   each role change, and the internal events handlers drop the
 *   tenant-level cache after each event. A TTL safety-net would
 *   only force needless re-population; remove it by default.
 *
 *   Predis's set() without the EX flag writes a persistent key
 *   that survives until explicit DEL. So the no-TTL path simply
 *   omits the EX argument.
 *
 *   Pass ttlSeconds=<positive int> to opt back into a TTL. Useful
 *   for staging environments with churn that would otherwise grow
 *   the keyspace unbounded.
 *
 *   IMPORTANT: must match the Helios-side cache. If Helios writes
 *   with one TTL and the SDK reads with another, the SDK's TTL
 *   wins on the next SDK-side set() call and may drop entries
 *   before Helios has a chance to re-write them.
 *
 * Error handling — best-effort, fail open:
 *
 *   - Get failures: log warn + return null (caller falls through to Helios).
 *   - Set / WriteThrough: log warn + return false. Caller decides —
 *     for the in-flight repopulate path, swallowing is fine.
 *   - Invalidate: log error + return. Stale data with no TTL safety
 *     net is sticky until the next WriteThrough for this user; that
 *     is the operator-visible signal.
 */
final class RedisPermissionCache implements PermissionCache
{
    public const KEY_PREFIX = 'helios:perms:';

    /**
     * Default TTL: 0 (no expiry). Entries are refreshed only by
     * explicit WriteThrough / Invalidate calls.
     *
     * Historical note: v0.1.0 shipped with a 60s default TTL as a
     * "safety net" for missed invalidations. It was removed when the
     * team moved to a write-through model — the explicit invalidates
     * on every mutation make the TTL redundant, and a 90-98%
     * cache-hit-rate platform needs the entries to stick around.
     */
    public const DEFAULT_TTL_SECONDS = 0;

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
        // Coerce negative TTLs to 0 (defensive — the old code coerced
        // them to the 60s default, which masked caller bugs).
        $ttl = $ttlSeconds ?? self::DEFAULT_TTL_SECONDS;
        if ($ttl < 0) {
            $ttl = 0;
        }
        $this->ttl = $ttl;
        $this->keyPrefix = $keyPrefix ?? self::KEY_PREFIX;
        $this->logger = $logger ?? new SilentLogger();
    }

    /**
     * Returns the configured TTL (0 = no expiry). Useful for
     * logging and cross-language parity tests.
     */
    public function getTtlSeconds(): int
    {
        return $this->ttl;
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
            // SET NX (no EX when ttl=0, the default). Predis exposes
            // set with options as positional args; we only pass EX
            // when configured to opt back into a TTL.
            $args = $this->ttl > 0
                ? [$this->key($userId, $tenantId), $payload, 'EX', $this->ttl, 'NX']
                : [$this->key($userId, $tenantId), $payload, 'NX'];
            $res = $this->redis->set(...$args);
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
            // SET (no NX, conditional EX) — explicit overwrite.
            // No KEEPTTL — this is a fresh write, not a refresh.
            $args = $this->ttl > 0
                ? [$this->key($userId, $tenantId), $payload, 'EX', $this->ttl]
                : [$this->key($userId, $tenantId), $payload];
            $this->redis->set(...$args);
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
            $this->logger->error('RedisPermissionCache.invalidate failed — cache will stay stale until the next WriteThrough for this user', [
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
            $this->logger->error('RedisPermissionCache.invalidateTenant failed — affected entries will be re-written on the next role change for each user', [
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
