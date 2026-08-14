<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Tests\Unit;

use Illuminate\Http\Client\Factory as HttpFactory;
use PHPUnit\Framework\TestCase;
use Wazobia\HeliosPermissions\Cache\InMemoryPermissionCache;
use Wazobia\HeliosPermissions\Events\HeliosUnreachableError;
use Wazobia\HeliosPermissions\HeliosClient;
use Wazobia\HeliosPermissions\Permission;
use Wazobia\HeliosPermissions\PermissionClient;

final class PermissionClientTest extends TestCase
{
    private function heliosReturning(string $secret, array $body, int $status = 200): HeliosClient
    {
        $http = new HttpFactory();
        $http->fake(['*' => $http->response($body, $status)]);
        return new HeliosClient('https://helios.example', $secret, null, $http);
    }

    public function test_caller_has_permission_cache_hit(): void
    {
        $cache = new InMemoryPermissionCache();
        $cache->set('u', 't', ['athens:project:delete']);
        $helios = $this->heliosReturning('x', ['status' => 'not_a_member'], 404);

        // Use athens:project:delete (OWNER-only) so the universal
        // short-circuit does NOT fire — only the cache hit should
        // short-circuit the lookup.
        $client = new PermissionClient($cache, $helios, false);
        $this->assertTrue($client->callerHasPermission('u', 't', Permission::AthensProjectDelete));
    }

    public function test_caller_has_permission_cache_miss_helios_ok(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', [
            'status' => 'active',
            'role' => 'EDITOR',
            // athens:project:view is universal-by-contract (short-circuit
            // returns true without consulting Helios). Use update as a
            // representative non-universal perm that IS in the EDITOR set.
            'permissions' => ['athens:project:view', 'athens:project:update'],
        ], 200);
        $client = new PermissionClient($cache, $helios);
        $this->assertTrue($client->callerHasPermission('u', 't', Permission::AthensProjectUpdate));
        $this->assertSame(['athens:project:view', 'athens:project:update'], $cache->get('u', 't'));
    }

    public function test_caller_has_permission_not_member_caches_empty(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', ['status' => 'not_a_member'], 404);
        $client = new PermissionClient($cache, $helios);
        // athens:project:delete is OWNER-only — short-circuit does not fire.
        $this->assertFalse($client->callerHasPermission('u', 't', Permission::AthensProjectDelete));
        $this->assertNotNull($cache->get('u', 't'));
        $this->assertSame([], $cache->get('u', 't'));
    }

    public function test_caller_has_permission_stale_on_error_true_returns_cache(): void
    {
        $cache = new InMemoryPermissionCache();
        $cache->set('u', 't', ['athens:project:delete']);
        $helios = $this->heliosReturning('x', ['error' => 'boom'], 500);
        $client = new PermissionClient($cache, $helios, true);
        $this->assertTrue($client->callerHasPermission('u', 't', Permission::AthensProjectDelete));
    }

    public function test_caller_has_permission_stale_on_error_false_propagates(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', ['error' => 'boom'], 500);
        $client = new PermissionClient($cache, $helios, false);
        $this->expectException(HeliosUnreachableError::class);
        // Use a non-universal perm so the short-circuit does not bypass Helios.
        $client->callerHasPermission('u', 't', Permission::AthensProjectDelete);
    }

    public function test_get_user_permissions(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', [
            'status' => 'active',
            'role' => 'OWNER',
            'permissions' => ['athens:project:view', 'athens:project:update', 'helios:tenant:switch'],
        ], 200);
        $client = new PermissionClient($cache, $helios);
        $perms = $client->getUserPermissions('u', 't');
        // v0.7.0 folds SELF_PERMISSIONS into the result, so we now see
        // the 3 role perms + every self-scope perm. Just verify the
        // expected presence/absence.
        $this->assertContains('athens:project:view', $perms);
        $this->assertContains('athens:project:update', $perms);
        $this->assertContains('helios:tenant:switch', $perms);
        $this->assertContains('mercury:user:write:self', $perms); // self-scope (folded in)
        $this->assertContains('mercury:user:read:self', $perms);
        $this->assertContains('mercury:user:delete:self', $perms);
    }

    // --- v0.7.0 short-circuit tests ---------------------------------------

    public function test_caller_has_permission_self_scope_short_circuits(): void
    {
        // self-scope perms are universal-by-contract — must return true
        // without consulting Helios. Critical for root-tenant users.
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning(
            'x',
            ['status' => 'not_a_member'],
            404,
        );
        $client = new PermissionClient($cache, $helios);
        $granted = $client->callerHasPermission(
            'root-platform-admin',
            'root-tenant-uuid',
            Permission::MercuryUserWriteSelf,
        );
        $this->assertTrue($granted);
        $this->assertNull($cache->get('root-platform-admin', 'root-tenant-uuid'),
            'short-circuit must not populate cache');
    }

    public function test_caller_has_permission_platform_perm_does_not_short_circuit_even_if_universal_by_role(): void
    {
        // isUniversalPerm is self-scope-only (db58c55): mercury:api_keys:read
        // is platform-scope and happens to be granted to all 4 roles, but
        // that must NOT short-circuit — platform/project/dual perms always
        // go through Helios so per-tenant authorization (e.g. a TenantRole
        // restricting a dual-scope perm) is still respected. With Helios
        // returning not_a_member, the caller must be denied.
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning(
            'x',
            ['status' => 'not_a_member'],
            404,
        );
        $client = new PermissionClient($cache, $helios);
        $granted = $client->callerHasPermission(
            'root-admin',
            'root-tenant',
            Permission::MercuryApiKeysRead,
        );
        $this->assertFalse($granted);
    }

    public function test_caller_has_permission_non_universal_still_consults_helios(): void
    {
        // mercury:api_keys:create is OWNER+ADMIN only. If a VIEWER asks
        // for it, the SDK must consult Helios and return false based on
        // the user's role.
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', [
            'status' => 'active',
            'role' => 'VIEWER',
            'permissions' => ['mercury:api_keys:read'], // NOT create
        ], 200);
        $client = new PermissionClient($cache, $helios);
        $this->assertFalse(
            $client->callerHasPermission('viewer', 't1', Permission::MercuryApiKeysCreate),
        );
    }

    public function test_explain_universal_perm_does_not_consult_helios(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning(
            'x',
            ['status' => 'not_a_member'],
            404,
        );
        $client = new PermissionClient($cache, $helios);
        $result = $client->explain(
            'root-admin',
            'root-tenant',
            Permission::MercuryUserWriteSelf,
        );
        $this->assertTrue($result['allowed']);
        $this->assertSame('granted_by_role', $result['reason']);
    }

    public function test_get_user_permissions_folds_self_scope_for_root_tenant_not_member(): void
    {
        // Without foldSelfPermissions, a root-tenant user (Helios returns
        // not_a_member) would see an empty perm array. With it, they see
        // at least the self-scope perms.
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning(
            'x',
            ['status' => 'not_a_member'],
            404,
        );
        $client = new PermissionClient($cache, $helios);
        $perms = $client->getUserPermissions('root-admin', 'root-tenant');
        $this->assertContains('mercury:user:write:self', $perms);
        $this->assertContains('mercury:user:read:self', $perms);
        $this->assertContains('mercury:user:delete:self', $perms);
    }

    public function test_explain_allowed(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', [
            'status' => 'active',
            'role' => 'EDITOR',
            'permissions' => ['athens:project:view'],
        ], 200);
        $client = new PermissionClient($cache, $helios);
        $exp = $client->explain('u', 't', Permission::AthensProjectView);
        $this->assertTrue($exp['allowed']);
        $this->assertSame('granted_by_role', $exp['reason']);
    }

    public function test_explain_denied(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', [
            'status' => 'active',
            'role' => 'EDITOR',
            'permissions' => ['athens:project:view'],
        ], 200);
        $client = new PermissionClient($cache, $helios);
        $exp = $client->explain('u', 't', Permission::AthensProjectUpdate);
        $this->assertFalse($exp['allowed']);
        $this->assertSame('not_in_role_perm_set', $exp['reason']);
    }

    public function test_write_through_populates_cache(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', ['status' => 'not_a_member'], 404);
        $client = new PermissionClient($cache, $helios);
        $client->writeThrough('u', 't', ['athens:project:view']);
        $this->assertSame(['athens:project:view'], $cache->get('u', 't'));
    }

    public function test_invalidate(): void
    {
        $cache = new InMemoryPermissionCache();
        $cache->set('u', 't', ['athens:project:view']);
        $helios = $this->heliosReturning('x', ['status' => 'not_a_member'], 404);
        $client = new PermissionClient($cache, $helios);
        $client->invalidate('u', 't');
        $this->assertNull($cache->get('u', 't'));
    }

    public function test_invalidate_tenant(): void
    {
        $cache = new InMemoryPermissionCache();
        $cache->set('u1', 'tA', ['athens:project:view']);
        $cache->set('u2', 'tA', ['athens:project:view']);
        $cache->set('u3', 'tB', ['athens:project:view']);
        $helios = $this->heliosReturning('x', ['status' => 'not_a_member'], 404);
        $client = new PermissionClient($cache, $helios);
        $client->invalidateTenant('tA');
        $this->assertNull($cache->get('u1', 'tA'));
        $this->assertNotNull($cache->get('u3', 'tB'));
    }
}
