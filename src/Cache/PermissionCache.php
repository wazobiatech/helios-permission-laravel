<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Cache;

use Wazobia\HeliosPermissions\Permission;

/**
 * PermissionCache is the cross-language cache interface for the
 * Wazobia Tech platform's permission cache. Mirrors the interface
 * shipped by the TS, Python, and Go SDKs.
 *
 * The contract:
 *
 *   - Get returns the cached perm array, or null on miss / error.
 *   - Set is NX: it does not overwrite an existing value. Used by
 *     the SDK's in-flight repopulate path so a slow read can't
 *     resurrect a value that was invalidated after the read started.
 *   - WriteThrough overwrites unconditionally. Helios's own writer
 *     (ZIN-4901i) calls this on every role change.
 *   - Invalidate drops a single (user, tenant) entry.
 *   - InvalidateTenant drops every entry for a tenant.
 *
 * Failure semantics are best-effort: implementors should log + swallow
 * on the write paths. The cache is the read-side substrate; the
 * upstream mutation has already committed and the 60s TTL is the
 * safety net.
 */
interface PermissionCache
{
    /**
     * @return Permission[]|null  null on miss or error.
     */
    public function get(string $userId, string $tenantId): ?array;

    /**
     * NX-set: returns true if the value was stored, false if the key
     * was already present (or on error). Best-effort — never throws.
     */
    public function set(string $userId, string $tenantId, array $perms): bool;

    /**
     * Unconditional overwrite. Best-effort — never throws.
     */
    public function writeThrough(string $userId, string $tenantId, array $perms): bool;

    public function invalidate(string $userId, string $tenantId): void;

    public function invalidateTenant(string $tenantId): void;
}
