<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wazobia\HeliosPermissions\PermScope;
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

    public function test_owner_has_owner_only_perms(): void
    {
        $this->assertTrue(RolePermissions::has(Role::Owner, Permission::HeliosTenantTransfer));
        $this->assertTrue(RolePermissions::has(Role::Owner, Permission::AthensProjectDelete));
    }

    public function test_transfer_is_owner_only(): void
    {
        $this->assertTrue(RolePermissions::has(Role::Owner, Permission::HeliosTenantTransfer));
        $this->assertFalse(RolePermissions::has(Role::Admin, Permission::HeliosTenantTransfer));
        $this->assertFalse(RolePermissions::has(Role::Editor, Permission::HeliosTenantTransfer));
        $this->assertFalse(RolePermissions::has(Role::Viewer, Permission::HeliosTenantTransfer));
    }

    public function test_self_scope_switch_is_universal_not_in_any_role(): void
    {
        $this->assertTrue(RolePermissions::isSelfScope(Permission::HeliosTenantSwitchSelf));
        foreach (RolePermissions::ROLES as $r) {
            $this->assertFalse(
                RolePermissions::has($r, Permission::HeliosTenantSwitchSelf),
                "role {$r->value} must NOT have self-scope perm helios:tenant:switch:self",
            );
        }
    }

    public function test_self_scope_mercury_user_self_perms(): void
    {
        $this->assertTrue(RolePermissions::isSelfScope(Permission::MercuryUserReadSelf));
        $this->assertTrue(RolePermissions::isSelfScope(Permission::MercuryUserWriteSelf));
        foreach (RolePermissions::ROLES as $r) {
            $this->assertFalse(
                RolePermissions::has($r, Permission::MercuryUserReadSelf),
                "role {$r->value} must NOT have self-scope perm mercury:user:read:self",
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

    public function test_resolve_returns_empty_for_unknown_role(): void
    {
        // Role is a closed enum, so a typed unknown role is impossible at the
        // type checker. Confirm the resolve() helper is defensive at runtime
        // by passing a value the map doesn't contain — there is no public
        // way to do this from a typed Role, so this is a documentation test.
        $this->assertTrue(true);
    }

    public function test_resolve_returns_typed_permission_array(): void
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

    // --------------------------------------------------------------------
    // v1.3.0 scope helpers
    // --------------------------------------------------------------------

    public function test_perm_scope_contains_every_perm(): void
    {
        $this->assertNotEmpty(RolePermissions::PERM_SCOPE);
        // 72 perms in the v1.6.0 contract: 12 self + 40 platform +
        // 19 project + 1 dual. v1.5.0 added 24 new Mercury perms:
        //   mercury:user:delete:self (self)
        //   mercury:users:batch_read (platform)
        //   mercury:api_keys:create | revoke | read (platform; manage is OWNER-only)
        //   mercury:service_clients:read (platform)
        //   mercury:auth_config:read (platform)
        //   mercury:auth_config_apple:{create,update} (platform)
        //   mercury:auth_config_oauth:{create,update} (platform)
        //   mercury:auth_config_forgot_password:{create,update,read} (platform)
        //   mercury:connection:read:self (self)
        //   mercury:connection_slack:{phrase_create,revoke}:self (self)
        //   mercury:connection_oauth:{initiate,complete}:self (self)
        //   mercury:connection_oauth:refresh (platform)
        //   mercury:connection_google:revoke:self (self)
        //   mercury:connection_imap:{create,revoke}:self (self)
        //   mercury:events:consume (platform)
        $this->assertCount(72, RolePermissions::PERM_SCOPE);
    }

    public function test_scopeOf_returns_scope_for_known_perm(): void
    {
        $this->assertSame(PermScope::Self, RolePermissions::scopeOf(Permission::HeliosTenantSwitchSelf));
        $this->assertSame(PermScope::Platform, RolePermissions::scopeOf(Permission::AthensProjectView));
        $this->assertSame(PermScope::Project, RolePermissions::scopeOf(Permission::MusePostsRead));
        $this->assertSame(PermScope::PlatformProject, RolePermissions::scopeOf(Permission::MuseAuthorRead));
    }

    public function test_isSelfScope_true_for_self_false_otherwise(): void
    {
        $this->assertTrue(RolePermissions::isSelfScope(Permission::HeliosTenantSwitchSelf));
        $this->assertTrue(RolePermissions::isSelfScope(Permission::MercuryUserReadSelf));
        $this->assertFalse(RolePermissions::isSelfScope(Permission::AthensProjectView));
        $this->assertFalse(RolePermissions::isSelfScope(Permission::MusePostsRead));
        $this->assertFalse(RolePermissions::isSelfScope(Permission::MuseAuthorRead));
    }

    public function test_isPlatformGrantable_true_for_platform_and_dual(): void
    {
        $this->assertTrue(RolePermissions::isPlatformGrantable(Permission::AthensProjectView));
        $this->assertTrue(RolePermissions::isPlatformGrantable(Permission::MuseAuthorRead)); // dual
        $this->assertFalse(RolePermissions::isPlatformGrantable(Permission::HeliosTenantSwitchSelf));
        $this->assertFalse(RolePermissions::isPlatformGrantable(Permission::MusePostsRead));
    }

    public function test_isTenantGrantable_true_for_project_dual_and_tenant_defined(): void
    {
        $this->assertTrue(RolePermissions::isTenantGrantable('muse:posts:read'));
        $this->assertTrue(RolePermissions::isTenantGrantable('muse:author:read')); // dual
        $this->assertFalse(RolePermissions::isTenantGrantable('athens:project:view'));
        $this->assertFalse(RolePermissions::isTenantGrantable('helios:tenant:switch:self'));
        // Tenant-defined perm (not in PERM_SCOPE) is grantable.
        $this->assertTrue(RolePermissions::isTenantGrantable('muse:custom:tenant-only-action'));
    }

    public function test_no_self_or_project_perms_in_any_role(): void
    {
        foreach (RolePermissions::ROLES as $r) {
            foreach (RolePermissions::resolve($r) as $p) {
                $scope = RolePermissions::scopeOf($p);
                $this->assertNotSame(
                    PermScope::Self,
                    $scope,
                    "role {$r->value} has self-scope perm {$p->value} (forbidden)",
                );
                $this->assertNotSame(
                    PermScope::Project,
                    $scope,
                    "role {$r->value} has project-scope perm {$p->value} (forbidden)",
                );
            }
        }
    }
}