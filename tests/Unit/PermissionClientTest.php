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
        $cache->set('u', 't', ['athens:project:view']);
        $helios = $this->heliosReturning('x', ['status' => 'not_a_member'], 404);

        // Pass staleOnError=false to ensure cache hit short-circuits
        // before reaching Helios.
        $client = new PermissionClient($cache, $helios, false);
        $this->assertTrue($client->callerHasPermission('u', 't', Permission::AthensProjectView));
    }

    public function test_caller_has_permission_cache_miss_helios_ok(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', [
            'status' => 'active',
            'role' => 'EDITOR',
            'permissions' => ['athens:project:view'],
        ], 200);
        $client = new PermissionClient($cache, $helios);
        $this->assertTrue($client->callerHasPermission('u', 't', Permission::AthensProjectView));
        $this->assertSame(['athens:project:view'], $cache->get('u', 't'));
    }

    public function test_caller_has_permission_not_member_caches_empty(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', ['status' => 'not_a_member'], 404);
        $client = new PermissionClient($cache, $helios);
        $this->assertFalse($client->callerHasPermission('u', 't', Permission::AthensProjectView));
        $this->assertNotNull($cache->get('u', 't'));
        $this->assertSame([], $cache->get('u', 't'));
    }

    public function test_caller_has_permission_stale_on_error_true_returns_cache(): void
    {
        $cache = new InMemoryPermissionCache();
        $cache->set('u', 't', ['athens:project:view']);
        $helios = $this->heliosReturning('x', ['error' => 'boom'], 500);
        $client = new PermissionClient($cache, $helios, true);
        $this->assertTrue($client->callerHasPermission('u', 't', Permission::AthensProjectView));
    }

    public function test_caller_has_permission_stale_on_error_false_propagates(): void
    {
        $cache = new InMemoryPermissionCache();
        $helios = $this->heliosReturning('x', ['error' => 'boom'], 500);
        $client = new PermissionClient($cache, $helios, false);
        $this->expectException(HeliosUnreachableError::class);
        $client->callerHasPermission('u', 't', Permission::AthensProjectView);
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
        $this->assertCount(3, $perms);
        $this->assertContains('helios:tenant:switch', $perms);
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
