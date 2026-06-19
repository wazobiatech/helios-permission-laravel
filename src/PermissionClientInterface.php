<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions;

/**
 * PermissionClientInterface — the public surface of the SDK.
 * Mirrors the TS / Python / Go SDKs.
 *
 *   1. Cache.Get(userId, tenantId) — hit returns the perm array.
 *   2. Cache miss → HeliosClient.FetchUserPermissions(userId, tenantId).
 *   3. On success: Cache.Set(...) (NX) + return the perms.
 *   4. On error: if staleOnError (default true) AND we have a
 *      cached value, return the cached value (fail-closed semantics —
 *      deny fresh, but allow stale). Otherwise throw.
 *
 * Write path (called by Helios, not by the SDK client itself): the
 * cache exposes WriteThrough / Invalidate / InvalidateTenant. Helios
 * calls these after every role change. See plan ZIN-4901i.
 */
interface PermissionClientInterface
{
    /**
     * @throws Events\HeliosUnreachableError when staleOnError=false
     *         and Helios is unreachable with no cache fallback.
     */
    public function callerHasPermission(string $userId, string $tenantId, Permission $perm): bool;

    /**
     * @return list<string>
     *
     * @throws Events\HeliosUnreachableError
     */
    public function getUserPermissions(string $userId, string $tenantId): array;

    /**
     * @return array{allowed: bool, reason: string, role?: string, permissions: list<string>}
     *
     * @throws Events\HeliosUnreachableError
     */
    public function explain(string $userId, string $tenantId, Permission $perm): array;

    public function invalidate(string $userId, string $tenantId): void;

    public function invalidateTenant(string $tenantId): void;

    /**
     * @param  list<string|Permission>  $perms
     */
    public function writeThrough(string $userId, string $tenantId, array $perms): void;
}
