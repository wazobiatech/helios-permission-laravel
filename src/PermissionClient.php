<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions;

use Wazobia\HeliosPermissions\Cache\PermissionCache;
use Wazobia\HeliosPermissions\Events\HeliosUnreachableError;
use Wazobia\HeliosPermissions\Support\Logger;
use Wazobia\HeliosPermissions\Support\SilentLogger;

/**
 * PermissionClient — the cache-first facade. Mirrors the TS / Python /
 * Go SDKs.
 *
 * Constructed by Factory::create(); do not instantiate directly.
 */
final class PermissionClient implements PermissionClientInterface
{
    public function __construct(
        private readonly PermissionCache $cache,
        private readonly HeliosClient $helios,
        private readonly bool $staleOnError = true,
        private readonly Logger $logger = new SilentLogger(),
    ) {
    }

    public function callerHasPermission(string $userId, string $tenantId, Permission $perm): bool
    {
        $perms = $this->fetchAndCache($userId, $tenantId);
        return in_array($perm->value, $perms, true);
    }

    public function getUserPermissions(string $userId, string $tenantId): array
    {
        return $this->fetchAndCache($userId, $tenantId);
    }

    public function explain(string $userId, string $tenantId, Permission $perm): array
    {
        $perms = $this->fetchAndCache($userId, $tenantId);
        if (in_array($perm->value, $perms, true)) {
            return [
                'allowed' => true,
                'reason' => 'granted_by_role',
                'permissions' => $perms,
            ];
        }
        return [
            'allowed' => false,
            'reason' => 'not_in_role_perm_set',
            'permissions' => $perms,
        ];
    }

    public function invalidate(string $userId, string $tenantId): void
    {
        $this->cache->invalidate($userId, $tenantId);
    }

    public function invalidateTenant(string $tenantId): void
    {
        $this->cache->invalidateTenant($tenantId);
    }

    public function writeThrough(string $userId, string $tenantId, array $perms): void
    {
        $this->cache->writeThrough($userId, $tenantId, $perms);
    }

    /**
     * @return list<string>
     *
     * @throws HeliosUnreachableError when staleOnError=false and the
     *         cache is empty + Helios is unreachable.
     */
    private function fetchAndCache(string $userId, string $tenantId): array
    {
        $cached = null;
        try {
            $cached = $this->cache->get($userId, $tenantId);
        } catch (\Throwable $e) {
            $this->logger->warn('cache.get failed; falling through to Helios', [
                'err' => $e->getMessage(),
                'userId' => $userId,
                'tenantId' => $tenantId,
            ]);
        }
        if ($cached !== null) {
            return $cached;
        }

        try {
            $res = $this->helios->fetchUserPermissions($userId, $tenantId);
        } catch (HeliosUnreachableError $e) {
            if ($this->staleOnError && $cached !== null) {
                return $cached;
            }
            throw $e;
        }

        $status = $res['status'] ?? '';
        if ($status !== 'active') {
            // not_a_member / inactive — cache an empty array so the
            // next read repopulates as "no perms" without re-hitting
            // Helios.
            $this->cache->set($userId, $tenantId, []);
            return [];
        }

        $perms = $res['permissions'] ?? [];
        if (!is_array($perms)) {
            $perms = [];
        }
        $perms = array_values(array_map('strval', $perms));
        $this->cache->set($userId, $tenantId, $perms);
        return $perms;
    }
}
