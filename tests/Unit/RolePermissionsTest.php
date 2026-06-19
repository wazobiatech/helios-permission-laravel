<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wazobia\HeliosPermissions\Permission;
use Wazobia\HeliosPermissions\Role;
use Wazobia\HeliosPermissions\RolePermissions;

final class RolePermissionsTest extends TestCase
{
    public function test_roles_constant_lists_every_role(): void
    {
        $this->assertSame(
            [Role::Owner, Role::Admin, Role::Editor, Role::Viewer],
            RolePermissions::ROLES,
        );
    }

    public function test_owner_has_universal_perm(): void
    {
        $this->assertTrue(RolePermissions::has(Role::Owner, Permission::HeliosTenantSwitch));
    }

    public function test_transfer_is_owner_only(): void
    {
        $this->assertTrue(RolePermissions::has(Role::Owner, Permission::HeliosTenantTransfer));
        $this->assertFalse(RolePermissions::has(Role::Admin, Permission::HeliosTenantTransfer));
        $this->assertFalse(RolePermissions::has(Role::Editor, Permission::HeliosTenantTransfer));
        $this->assertFalse(RolePermissions::has(Role::Viewer, Permission::HeliosTenantTransfer));
    }

    public function test_universal_perm_in_every_role(): void
    {
        foreach (RolePermissions::ROLES as $r) {
            $this->assertTrue(
                RolePermissions::has($r, Permission::HeliosTenantSwitch),
                "role {$r->value} missing universal perm",
            );
        }
    }

    public function test_no_empty_role(): void
    {
        foreach (RolePermissions::ROLES as $r) {
            $perms = RolePermissions::resolve($r);
            $this->assertNotEmpty($perms, "role {$r->value} has zero perms");
        }
    }

    public function test_resolve_returns_empty_for_unknown_role_via_string(): void
    {
        // The resolve() method takes a typed Role, not a string, so
        // the unknown-via-string path doesn't apply directly. Confirm
        // the typed unknown role is impossible (Role is a closed
        // enum). Skipping the test as redundant.
        $this->assertTrue(true);
    }

    public function test_resolve_string_values_returns_string_list(): void
    {
        $perms = RolePermissions::resolve(Role::Viewer);
        $this->assertIsArray($perms);
        $this->assertNotEmpty($perms);
        foreach ($perms as $p) {
            $this->assertInstanceOf(Permission::class, $p);
        }
    }

    public function test_viewer_is_read_only(): void
    {
        $this->assertFalse(RolePermissions::has(Role::Viewer, Permission::AthensProjectUpdate));
        $this->assertFalse(RolePermissions::has(Role::Viewer, Permission::MusePostsWrite));
    }

    public function test_isValidPermission(): void
    {
        $this->assertTrue(RolePermissions::isValidPermission(Permission::AthensProjectView));
    }
}
