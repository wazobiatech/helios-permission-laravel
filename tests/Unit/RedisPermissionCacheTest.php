<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Tests\Unit;

use Mockery;
use PHPUnit\Framework\TestCase;
use Predis\ClientInterface;
use Wazobia\HeliosPermissions\Cache\RedisPermissionCache;
use Wazobia\HeliosPermissions\Permission;
use Wazobia\HeliosPermissions\Support\SilentLogger;

/**
 * RedisPermissionCache — unit tests using a Mockery-backed Predis
 * client. We do NOT need a real Redis: the contract pins the set()
 * argument shape (EX + NX), not the Redis wire protocol.
 *
 * v0.3.0 — no-TTL default. The cache omits the EX argument when
 * ttl=0 (matches go-redis `time.Duration(0)` PERSIST semantics and
 * the TS / Python SDK behavior).
 */
final class RedisPermissionCacheTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
    }

    public function test_default_constructor_has_no_ttl(): void
    {
        $redis = Mockery::mock(ClientInterface::class);
        $cache = new RedisPermissionCache($redis, null, null, new SilentLogger());
        $this->assertSame(0, $cache->getTtlSeconds());
    }

    public function test_set_omits_ex_when_ttl_zero(): void
    {
        $redis = Mockery::mock(ClientInterface::class);
        // Default ttl=0 → set(key, payload, 'NX') — no EX arg.
        $redis->shouldReceive('set')
            ->once()
            ->with('helios:perms:u-1:t-1', Mockery::type('string'), 'NX')
            ->andReturn('OK');

        $cache = new RedisPermissionCache($redis, null, null, new SilentLogger());
        $this->assertTrue($cache->set('u-1', 't-1', [Permission::AthensProjectView]));
    }

    public function test_set_includes_ex_when_ttl_positive(): void
    {
        $redis = Mockery::mock(ClientInterface::class);
        // ttl=120 → set(key, payload, 'EX', 120, 'NX').
        $redis->shouldReceive('set')
            ->once()
            ->with('helios:perms:u-1:t-1', Mockery::type('string'), 'EX', 120, 'NX')
            ->andReturn('OK');

        $cache = new RedisPermissionCache($redis, 120, null, new SilentLogger());
        $this->assertTrue($cache->set('u-1', 't-1', [Permission::AthensProjectView]));
    }

    public function test_write_through_omits_ex_when_ttl_zero(): void
    {
        $redis = Mockery::mock(ClientInterface::class);
        // Default ttl=0 → set(key, payload) — no EX, no NX.
        $redis->shouldReceive('set')
            ->once()
            ->with('helios:perms:u-1:t-1', Mockery::type('string'))
            ->andReturn('OK');

        $cache = new RedisPermissionCache($redis, null, null, new SilentLogger());
        $this->assertTrue($cache->writeThrough('u-1', 't-1', [Permission::AthensProjectView]));
    }

    public function test_write_through_includes_ex_when_ttl_positive(): void
    {
        $redis = Mockery::mock(ClientInterface::class);
        $redis->shouldReceive('set')
            ->once()
            ->with('helios:perms:u-1:t-1', Mockery::type('string'), 'EX', 60)
            ->andReturn('OK');

        $cache = new RedisPermissionCache($redis, 60, null, new SilentLogger());
        $this->assertTrue($cache->writeThrough('u-1', 't-1', [Permission::AthensProjectView]));
    }

    public function test_negative_ttl_coerced_to_zero(): void
    {
        $redis = Mockery::mock(ClientInterface::class);
        // Defensive coercion — negative TTL is nonsensical; we treat
        // it the same as 0 (no expiry).
        $cache = new RedisPermissionCache($redis, -1, null, new SilentLogger());
        $this->assertSame(0, $cache->getTtlSeconds());
    }

    public function test_key_shape_is_cross_language_contract(): void
    {
        // Pins the key prefix against the TS / Python / Go SDKs.
        // Drift here would silently break every cross-language consumer.
        $redis = Mockery::mock(ClientInterface::class);
        $redis->shouldReceive('set')
            ->once()
            ->with('helios:perms:alice:tenant-7', Mockery::type('string'), 'NX')
            ->andReturn('OK');

        $cache = new RedisPermissionCache($redis, null, null, new SilentLogger());
        $cache->set('alice', 'tenant-7', [Permission::AthensProjectView]);
        // Mockery's shouldReceive(...)->once() asserts the call shape;
        // PHPUnit's Mockery integration doesn't auto-count that as an
        // assertion, so we explicitly bump the counter.
        $this->addToAssertionCount(1);
    }
}