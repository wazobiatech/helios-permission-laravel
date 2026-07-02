<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions;

use Wazobia\HeliosPermissions\Cache\PermissionCache;
use Wazobia\HeliosPermissions\Events\HeliosUnreachableError;
use Wazobia\HeliosPermissions\RolePermissions;
use Wazobia\HeliosPermissions\Support\Logger;
use Wazobia\HeliosPermissions\Support\SilentLogger;

/**
 * PermissionClient — the cache-first facade. Mirrors the TS / Python /
 * Go SDKs.
 *
 * Constructed by Factory::create(); do not instantiate directly.
 *
 * Cache TTL: the default cache has NO TTL — entries live until
 * explicit DEL via Invalidate / InvalidateTenant (or via Helios's
 * sync write-through on every role-changing mutation). The cache is
 * the primary read path for callerHasPermission and we target a
 * 90-98% hit rate; entries must outlive the request burst. Pass
 * cache_ttl_seconds in the Factory config to opt back into a TTL.
 * Both Helios-side and SDK-side caches must use the same TTL policy.
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
        // Universal perms (self-scope or granted to every role) short-circuit
        // to true without consulting cache or Helios. Critical for root-tenant
        // users (Mercury's platform admins) who have no Helios membership row.
        // See RolePermissions::isUniversalPerm().
        if (RolePermissions::isUniversalPerm($perm)) {
            return true;
        }
        $perms = $this->fetchAndCache($userId, $tenantId);
        return in_array($perm->value, $perms, true);
    }

    public function getUserPermissions(string $userId, string $tenantId): array
    {
        $rolePerms = $this->fetchAndCache($userId, $tenantId);
        // Self-scope perms are universal by contract — fold them in so the
        // caller sees a complete view regardless of tenant membership.
        return $this->foldSelfPermissions($rolePerms);
    }

    public function explain(string $userId, string $tenantId, Permission $perm): array
    {
        // Universal perms are granted by contract — no Helios lookup needed.
        if (RolePermissions::isUniversalPerm($perm)) {
            return [
                'allowed' => true,
                'reason' => 'granted_by_role',
                'permissions' => $this->foldSelfPermissions([]),
            ];
        }
        $perms = $this->fetchAndCache($userId, $tenantId);
        $fullPerms = $this->foldSelfPermissions($perms);
        if (in_array($perm->value, $perms, true)) {
            return [
                'allowed' => true,
                'reason' => 'granted_by_role',
                'permissions' => $fullPerms,
            ];
        }
        return [
            'allowed' => false,
            'reason' => 'not_in_role_perm_set',
            'permissions' => $fullPerms,
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
    private function foldSelfPermissions(array $rolePerms): array
    {
        // Self-scope perms (e.g. mercury:user:write:self) are universal by
        // contract — every authenticated user has them regardless of role
        // or tenant membership. We always fold SELF_PERMISSIONS into the
        // result so callers see a complete view. Without this, root-tenant
        // users (Mercury's platform admins, who have no Helios membership
        // row) would show an empty perm array even though they can mutate
        // their own profile.
        $selfPerms = array_map(
            static fn (Permission $p): string => $p->value,
            array_filter(
                Permission::cases(),
                static fn (Permission $p): bool => RolePermissions::isSelfScope($p),
            ),
        );
        return array_values(array_unique(array_merge($selfPerms, $rolePerms)));
    }

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
