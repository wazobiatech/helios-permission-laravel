# HANDOFF — wazobia/helios-permissions (Laravel SDK)

Status snapshot for the Laravel SDK mirror of
`@wazobiatech/helios-permissions`.

## TL;DR

Laravel SDK shipped. Mirrors the TS / Python / Go SDKs' cache-first
`callerHasPermission` surface. Auto-discovered service provider
binds `PermissionClientInterface` as a singleton. Codegen is wired
against `wazobiatech/permission-contract@v1.0.0` and the CI pipeline
fails on drift. Tag `v0.1.0` to publish.

## What's in v0.1.0

- `PermissionClientInterface` (public surface): `callerHasPermission`, `getUserPermissions`, `explain`, `invalidate`, `invalidateTenant`, `writeThrough`.
- `Factory::create(array $config): PermissionClientResult` wires `HeliosClient` + `RedisPermissionCache` + `PermissionClient`. Owns Predis lifecycle when given a URL; respects injected lifecycle.
- `InMemoryPermissionCache` for tests and single-instance dev.
- `RedisPermissionCache` (predis): key shape `helios:perms:{userId}:{tenantId}`, 60s TTL, NX on `set`, overwrite on `writeThrough`, SCAN-based `invalidateTenant`.
- HMAC signing matches the TS / Python / Go SDKs and Helios's `hmac.ts` verifier: `METHOD + path + timestamp` (path WITHOUT query string).
- `HeliosPermissionsServiceProvider` auto-discovered; binds `PermissionClientInterface` as singleton; publishes config.
- `bin/codegen` PHP-native emitter (alternative to the Node emitter).
- 41 tests in `tests/Unit/`; `vendor/bin/phpunit` is green.

## Why this lives in its own package

- Different runtime (PHP vs TS / Python / Go).
- Different release cadence (Laravel ecosystem vs Node / Python / Go ecosystems).
- Pinning the contract version per-SDK (via the codegen fixture test) is easier when each SDK has its own `RolePermissions.php` checked in.
- The auto-discovered service provider is the Laravel-idiomatic integration point.

## Critical files

| File | Purpose |
|---|---|
| `src/Role.php` | GENERATED from `permission-contract/permissions.json`. Closed `Role` enum. |
| `src/Permission.php` | GENERATED. Closed `Permission` enum. |
| `src/RolePermissions.php` | GENERATED. Role → perm map + helpers. |
| `src/Cache/PermissionCache.php` | Interface. |
| `src/Cache/RedisPermissionCache.php` | Production cache impl. Key shape pinned here. |
| `src/Cache/InMemoryPermissionCache.php` | Process-local impl. |
| `src/HeliosClient.php` | HMAC transport (Laravel `Http` facade). |
| `src/PermissionClient.php` | Cache-first facade. Implements `PermissionClientInterface`. |
| `src/PermissionClientInterface.php` | Public surface. |
| `src/Factory.php`, `src/PermissionClientResult.php` | Factory + result. |
| `src/HeliosPermissionsServiceProvider.php` | Auto-discovered; binds the singleton. |
| `src/Events/HeliosUnreachableError.php` | Thrown by `HeliosClient` on upstream failure. |
| `src/Support/{Logger,SilentLogger,ConsoleLogger}.php` | Minimal logging surface. |
| `config/helios-permissions.php` | Published config. |
| `bin/codegen` | PHP-native emitter. |
| `tests/Unit/*` | 41 tests; `vendor/bin/phpunit` is green. |
| `bitbucket-pipelines.yml` | composer install → phpunit → codegen-diff. |

## Dependencies

| Package | Version | Why |
|---|---|---|
| `php` | `^8.1` | Backed enums. |
| `predis/predis` | `^2.2` | Pure-PHP Redis client. No PECL required. |
| `illuminate/http` | `^10\|^11\|^12` | `Http` facade for the Helios transport. |
| `illuminate/support` | `^10\|^11\|^12` | Service provider base class. |
| `phpunit/phpunit` | `^10.0` (dev) | Test runner. |
| `mockery/mockery` | `^1.6` (dev) | Test doubles for the factory test. |

## Architecture decisions

- **HMAC deviation.** `METHOD + path + timestamp` (path WITHOUT query string) — same as the TS / Python / Go SDKs. Helios's internal `hmac.ts` verifier signs the same way. When Helios's verifier is fixed to canonical, this client updates in lockstep.
- **Cache key shape.** `helios:perms:{userId}:{tenantId}`. The cross-language contract — must match Helios's writer and the TS / Python / Go SDKs.
- **Cache TTL = 60s.** Safety net for invalidation failures. Matches the TS / Python / Go SDKs.
- **`stale_on_error=true` by default.** Fail-closed: allow stale on Helios error so a brief Helios outage doesn't lock everyone out. Matches the TS / Python / Go SDKs.
- **Factory-owned Predis lifecycle.** `Factory::create` disconnects the Predis client it built (when given a URL) and leaves injected clients alone.
- **Auto-discovered service provider.** The Laravel-idiomatic integration point. `composer require` is enough; no `config/app.php` edit needed.
- **Predis, not phpredis.** Pure-PHP Composer package, no PECL extension install. The cost is a small performance hit (~2x slower than phpredis on hot paths) — irrelevant for the SDK, which is **not** a hot path.

## How to publish

```bash
git tag v0.1.0
git push origin v0.1.0
```

Push to a private Packagist registry or the consumer's `repositories`
entry pointing at the GitHub mirror.

## How to consume

```php
// composer.json
{
  "require": {
    "wazobia/helios-permissions": "^0.1.0"
  }
}

// .env
HELIOS_BASE_URL=https://helios.svc
SIGNATURE_SHARED_SECRET=...
PERMISSION_REDIS_URL=redis://...

// app/Http/Controllers/...
use Wazobia\HeliosPermissions\Permission;
use Wazobia\HeliosPermissions\PermissionClientInterface;

class MyController
{
    public function __construct(private PermissionClientInterface $perms) {}

    public function show(string $userId, string $tenantId)
    {
        if (!$this->perms->callerHasPermission($userId, $tenantId, Permission::AthensProjectView)) {
            abort(403);
        }
        // ...
    }
}
```

## Known issues

- **No event-driven invalidator.** Per the plan, v1 of the Go / Laravel SDKs relies on the 60s TTL + Helios's `writeThrough`. A follow-up ticket can add a Kafka consumer if a Laravel service needs real-time event-driven invalidation.
- **No service-tagged `CacheInterface` adapter.** A future ticket could add a PSR-16 cache abstraction; v1 uses predis directly per the user's choice.

## Future work

- Add a Laravel `Cache` driver (e.g. `helios-permissions`) so consumers can swap the underlying cache without rewiring.
- Investigate a `Mockery` test helper package for downstream services.
- Investigate a `Http::fake()` helper for downstream service tests.

## Verification

Local:

```bash
composer install
vendor/bin/phpunit
php bin/codegen ../permission-contract/permissions.json src/
# diff against committed files
```

CI runs all three steps on every push; tag-driven `v*` builds also re-run them.
