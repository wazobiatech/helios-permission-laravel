<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Cache;

use Wazobia\HeliosPermissions\Permission;

/**
 * InMemoryPermissionCache — process-local PermissionCache impl.
 *
 * Use for tests and single-instance dev. Production uses
 * RedisPermissionCache.
 *
 * Concurrency: PHP-FPM is single-threaded per request, so no lock is
 * needed across requests — each request sees the array snapshot at
 * its start. Long-running workers (Octane, Swoole) should use
 * RedisPermissionCache.
 */
final class InMemoryPermissionCache implements PermissionCache
{
    /** @var array<string, list<string>> userId:tenantId → perms */
    private array $store = [];

    private function key(string $userId, string $tenantId): string
    {
        return $userId . ':' . $tenantId;
    }

    public function get(string $userId, string $tenantId): ?array
    {
        $k = $this->key($userId, $tenantId);
        if (!array_key_exists($k, $this->store)) {
            return null;
        }
        // Defensive copy so callers can't mutate the shared store.
        return $this->store[$k];
    }

    public function set(string $userId, string $tenantId, array $perms): bool
    {
        $k = $this->key($userId, $tenantId);
        if (array_key_exists($k, $this->store)) {
            return false;
        }
        $this->store[$k] = $this->normalize($perms);
        return true;
    }

    public function writeThrough(string $userId, string $tenantId, array $perms): bool
    {
        $this->store[$this->key($userId, $tenantId)] = $this->normalize($perms);
        return true;
    }

    public function invalidate(string $userId, string $tenantId): void
    {
        unset($this->store[$this->key($userId, $tenantId)]);
    }

    public function invalidateTenant(string $tenantId): void
    {
        $suffix = ':' . $tenantId;
        foreach (array_keys($this->store) as $k) {
            if (str_ends_with($k, $suffix)) {
                unset($this->store[$k]);
            }
        }
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
