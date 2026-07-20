# HANDOFF — wazobia/helios-permissions (Laravel SDK)

Status snapshot for the Laravel SDK mirror of
`@wazobiatech/helios-permissions`.

## TL;DR

Laravel SDK shipped. Mirrors the TS / Python / Go SDKs' cache-first
`callerHasPermission` surface. Auto-discovered service provider
binds `PermissionClientInterface` as a singleton. Codegen is wired
against `wazobiatech/permission-contract@v1.7.0` and the CI pipeline
fails on drift. Tag `v0.8.0` to publish.

## What's in v0.8.0

- `PermissionClientInterface` (public surface): `callerHasPermission`, `getUserPermissions`, `explain`, `invalidate`, `invalidateTenant`, `writeThrough`.
- `Factory::create(array $config): PermissionClientResult` wires `HeliosClient` + `RedisPermissionCache` + `PermissionClient`. Owns Predis lifecycle when given a URL; respects injected lifecycle.
- `InMemoryPermissionCache` for tests and single-instance dev.
- `RedisPermissionCache` (predis): key shape `helios:perms:{userId}:{tenantId}`, **no TTL by default** (Predis `set` without `EX` → PERSIST), NX on `set`, overwrite on `writeThrough`, SCAN-based `invalidateTenant`. Pass `cache_ttl_seconds=<positive int>` in the config to opt back into a TTL.
- HMAC signing matches the TS / Python / Go SDKs and Helios's `hmac.ts` verifier: `METHOD + path + timestamp` (path WITHOUT query string).
- `HeliosPermissionsServiceProvider` auto-discovered; binds `PermissionClientInterface` as singleton; publishes config.
- `bin/codegen` PHP-native emitter (alternative to the Node emitter).
- **v0.7.0 universal-by-contract short-circuit** — `callerHasPermission` returns `true` without consulting Helios when the perm is in every role's `ROLE_PERMISSIONS` entry (or is self-scope). Mirrors the TS / Python SDK v0.7.0 behavior. Critical for root-tenant users who have no Helios membership row.
- 62 tests in `tests/Unit/`; `vendor/bin/phpunit` is green.

### Changes from v0.6.0

- **Universal-by-contract short-circuit (additive behavior change).**
  `PermissionClient::callerHasPermission` and `PermissionClient::explain`
  now return `true` without consulting Helios (or the cache) when the
  requested perm is universal by contract — i.e. the perm is either
  self-scope (universal by contract invariant) or appears in every
  role's `ROLE_PERMISSIONS` entry. `getUserPermissions` folds the
  self-scope perms into its result so callers see a complete view
  regardless of tenant membership.

  Why this exists: Helios stores per-(user, tenant) membership rows.
  Root-tenant users (Mercury's platform admins) and any other
  tenantless caller have no row to look up. Without this short-circuit,
  every `callerHasPermission` for a universal perm would resolve to
  `not_a_member` and 403 the caller. The contract invariant is that
  these perms do NOT depend on tenant membership — they are universal.
  Adding a perm to all four roles is a deliberate, reviewable contract
  decision; the SDK honors it without re-fetching.
- **`RolePermissions::isUniversalPerm(Permission)` helper.** Codegen'd
  from `permission-contract/permissions.json` and exposed on the
  generated `RolePermissions` class. The Laravel PHP emitter (`bin/codegen`)
  is kept in lockstep with the contract repo's Node emitter
  (`permission-contract/scripts/codegen-php.mjs`).
- **Permission-contract v1.6.0.** Adds Mercury expansion (24 new perms
  in v1.5.0; v1.6.0 carries the same vocabulary plus scope-grouped
  emitter ordering for stable diffs).
- **Test fixtures regenerated.** `tests/fixtures/{Role,Permission,PermScope,RolePermissions}.php.expected`
  updated against v1.6.0 contract. `tests/Unit/RolePermissionsTest::test_perm_scope_contains_every_perm`
  bumped to expect 72 perms (12 self + 40 platform + 19 project + 1 dual).

### Changes from v0.7.0

- **Permission-contract v1.7.0.** Regenerates `Role.php`, `Permission.php`,
  `PermScope.php`, `RolePermissions.php` from the v1.7.0 contract. Adds
  17 new `muse:*` permissions (blog update/delete, author update,
  tag/category/redirect CRUD, redirect analytics, posts:revert).
  `muse:posts:delete` scope bumped from `project` to `platform/project`
  so it can be granted via `role_permissions` to OWNER/ADMIN/EDITOR (the
  muse:posts resource is platform-owned — previously project-scoped would
  only be reachable through TenantRole). `muse:blog:delete` added to
  `owner_only_permissions` (5 → 6 entries). No SDK behavior change —
  purely a vocabulary bump. `tests/Unit/RolePermissionsTest::test_perm_scope_contains_every_perm`
  bumped to expect 89 perms (12 self + 43 platform + 18 project + 16 dual).

### Changes from v0.2.0

- **No-TTL cache default.** v0.2.0 shipped with a 60s default TTL.
  v0.3.0 removes it. `RedisPermissionCache::DEFAULT_TTL_SECONDS = 0`
  (matches the TS, Python, and Go SDKs at v0.5.0 / v0.5.0 / v0.2.0).
  Entries live until explicit DEL. Rationale: the cache is the
  primary read path for `callerHasPermission` and we target a
  90-98% hit rate; entries must outlive the request burst. Every
  entry is invalidated explicitly at the mutation site. Pass
  `cache_ttl_seconds=<positive int>` to the Factory config to opt
  back in.
- **Permission-contract v1.4.0.** Adds `helios:external:register /
  revoke / view` (Use case 2 — "tenant brings their own auth") and
  `athens:team:invite / remove`. Renames `helios:tenant:switch` →
  `helios:tenant:switch:self` with scope `self` (universal perm).

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

- **No event-driven invalidator.** Per the plan, v1 of the Go / Laravel SDKs relies on the no-TTL cache + Helios's `writeThrough`. A follow-up ticket can add a Kafka consumer if a Laravel service needs real-time event-driven invalidation.
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
