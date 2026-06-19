<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wazobia\HeliosPermissions\Cache\InMemoryPermissionCache;

final class InMemoryPermissionCacheTest extends TestCase
{
    public function test_get_miss_on_empty(): void
    {
        $c = new InMemoryPermissionCache();
        $this->assertNull($c->get('u', 't'));
    }

    public function test_set_then_get(): void
    {
        $c = new InMemoryPermissionCache();
        $this->assertTrue($c->set('u', 't', ['athens:project:view', 'athens:project:update']));
        $this->assertSame(['athens:project:view', 'athens:project:update'], $c->get('u', 't'));
    }

    public function test_set_is_nx(): void
    {
        $c = new InMemoryPermissionCache();
        $this->assertTrue($c->set('u', 't', ['athens:project:view']));
        $this->assertFalse($c->set('u', 't', ['athens:project:update']));
        $this->assertSame(['athens:project:view'], $c->get('u', 't'));
    }

    public function test_write_through_overwrites(): void
    {
        $c = new InMemoryPermissionCache();
        $c->set('u', 't', ['athens:project:view']);
        $this->assertTrue($c->writeThrough('u', 't', ['athens:project:update']));
        $this->assertSame(['athens:project:update'], $c->get('u', 't'));
    }

    public function test_invalidate(): void
    {
        $c = new InMemoryPermissionCache();
        $c->set('u', 't', ['athens:project:view']);
        $c->invalidate('u', 't');
        $this->assertNull($c->get('u', 't'));
    }

    public function test_invalidate_tenant_drops_matching_suffix(): void
    {
        $c = new InMemoryPermissionCache();
        $c->set('u1', 'tA', ['athens:project:view']);
        $c->set('u2', 'tA', ['athens:project:view']);
        $c->set('u3', 'tB', ['athens:project:view']);
        $c->invalidateTenant('tA');
        $this->assertNull($c->get('u1', 'tA'));
        $this->assertNull($c->get('u2', 'tA'));
        $this->assertNotNull($c->get('u3', 'tB'));
    }
}
