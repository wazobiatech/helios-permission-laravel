# wazobia/helios-permissions (Laravel SDK)

Laravel SDK for cross-service authorization in the Wazobia Tech
platform. Cache-first `callerHasPermission` / `getUserPermissions` /
`explain` / `invalidate` / `writeThrough` surface, mirroring the
TypeScript, Python, and Go SDKs.

## What it does

A single `PermissionClientInterface` answers "is user U allowed perm P
in tenant T?" with:

1. **Cache hit** — returns the cached perm array (Redis GET, sub-ms).
2. **Cache miss** — calls Helios's `GET /internal/permissions/:userId?tenantId=<uuid>`,
   which is HMAC-signed with `SIGNATURE_SHARED_SECRET`. Populates the
   cache with the new perms.
3. **Helios unreachable + `stale_on_error=true` (default)** — returns
   the cached value (fail-closed: allow stale, deny fresh).
4. **Helios unreachable + `stale_on_error=false`** — throws
   `HeliosUnreachableError`.

`writeThrough` / `invalidate` / `invalidateTenant` are the write path
that Helios itself calls after every role-changing mutation. See
[helios's `permission-cache.service.ts`](../helios/src/internal/permission-cache.service.ts)
(ZIN-4901i).

## Installation

```bash
composer require wazobia/helios-permissions
```

The package auto-discovers its service provider. Publish the config:

```bash
php artisan vendor:publish --tag=helios-permissions-config
```

## Quick start

```php
use Wazobia\HeliosPermissions\Factory;
use Wazobia\HeliosPermissions\Permission;
use Wazobia\HeliosPermissions\PermissionClientInterface;

class MyService
{
    public function __construct(private PermissionClientInterface $perms) {}

    public function view(string $userId, string $tenantId): bool
    {
        return $this->perms->callerHasPermission(
            $userId,
            $tenantId,
            Permission::AthensProjectView,
        );
    }
}
```

Or, without auto-discovery, wire it manually:

```php
$r = Factory::create(config('helios-permissions'));
$allowed = $r->client->callerHasPermission($userId, $tenantId, Permission::AthensProjectView);
($r->close)(); // on shutdown
```

## Configuration

| Env var | Purpose | Required |
|---|---|---|
| `HELIOS_BASE_URL` | Helios service base URL | yes |
| `SIGNATURE_SHARED_SECRET` | HMAC shared secret for Helios auth | yes |
| `PERMISSION_REDIS_URL` | Redis URL for the shared permission cache | yes |
| `HELIOS_SOURCE_SERVICE` | `x-source-service` header (default `helios-permissions-laravel`) | no |
| `CACHE_TTL_SECONDS` | Cache TTL — defaults to `0` (no expiry; entries live until explicit DEL). Pass a positive int to opt back into a TTL. | no |
| `HELIOS_FETCH_TIMEOUT_SECONDS` | Per-fetch timeout to Helios (default `2.0`) | no |
| `STALE_ON_ERROR` | `1`/`true` = allow stale on Helios error; default `1` | no |
| `HELIOS_PERMISSIONS_LOGGER` | `silent` / `console` / a `Logger` instance | no |

`PERMISSION_REDIS_URL` is **the same Redis Helios writes to**. Sharing
the instance is the point: Helios's `writeThrough` keeps every
service's cache fresh after a role change. This is the key invariant
that makes the cross-language SDKs correct.

## Public surface

```php
interface PermissionClientInterface
{
    public function callerHasPermission(string $userId, string $tenantId, Permission $perm): bool;
    public function getUserPermissions(string $userId, string $tenantId): array;
    public function explain(string $userId, string $tenantId, Permission $perm): array;
    public function invalidate(string $userId, string $tenantId): void;
    public function invalidateTenant(string $tenantId): void;
    public function writeThrough(string $userId, string $tenantId, array $perms): void;
}

final class Factory
{
    public static function create(array $config): PermissionClientResult;
}

final class PermissionClientResult
{
    public PermissionClientInterface $client;
    public \Predis\ClientInterface $redis;
    public \Closure $close;
}
```

`Permission` and `Role` are typed PHP 8.1 backed enums — typos fail
at compile time.

## HMAC contract

The SDK signs requests the same way the TS / Python / Go SDKs do,
and the same way Helios's internal `hmac.ts` verifier expects:

```
payload  = METHOD + path + timestamp      // METHOD is "GET" (uppercase)
digest   = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
headers  = x-source-service, x-signature, x-timestamp
reject   if |now - timestamp| > 300s
```

The path is signed **without** the query string. This matches
Helios's deviation from the canonical nexus-mcp contract. When
Helios's verifier is fixed to canonical, this client updates in
lockstep with the TS / Python / Go SDKs.

## Cache key shape

```
helios:perms:{userId}:{tenantId}    →    JSON array of permission strings
```

The key shape is the cross-language contract — must match Helios's
`permission-cache.service.ts` and the TS / Python / Go SDKs. Drift
here would silently break every consumer.

## Cache TTL policy (v0.3.0 — no expiry by default)

The default cache has **no TTL**. Entries live until explicit DEL
via `invalidate` / `invalidateTenant` (or via Helios's sync
`writeThrough` on every role-changing mutation). The cache is the
primary read path for `callerHasPermission` and we target a 90-98%
hit rate; entries must outlive the request burst. Every entry is
invalidated explicitly at the mutation site — Helios calls
`writeThrough` / `invalidate` after every role change, and the
internal events handlers (`athens.project.*`, `athens.service.update`,
`mercury.user.deleted`, `helios.invitation.accepted`) invalidate the
tenant-level cache after each event. A 60s safety-net TTL would just
be wasted work — entries the next read would re-populate anyway.

Pass `cache_ttl_seconds: <positive int>` in the Factory config to opt
back into a TTL. **Both Helios-side and SDK-side caches must use the
same TTL policy** — if Helios writes with one TTL and the SDK reads
with another, the SDK's TTL wins on the next SDK-side `set` call and
may drop entries before Helios has a chance to re-write them.

## Architecture

- `src/Role.php`, `src/Permission.php`, `src/RolePermissions.php` — **generated** from `permission-contract/permissions.json`. Do not edit by hand.
- `src/Cache/PermissionCache.php` — interface.
- `src/Cache/InMemoryPermissionCache.php` — process-local impl. For tests and single-instance dev.
- `src/Cache/RedisPermissionCache.php` — Redis impl (predis). The production choice.
- `src/HeliosClient.php` — HMAC-signed transport to `GET /internal/permissions/:userId`. Uses Laravel's `Http` facade.
- `src/PermissionClient.php` — cache-first facade. Implements `PermissionClientInterface`.
- `src/PermissionClientInterface.php` — the public surface.
- `src/Factory.php` + `src/PermissionClientResult.php` — `create()` factory + result type.
- `src/HeliosPermissionsServiceProvider.php` — auto-discovered.
- `src/Events/HeliosUnreachableError.php` — thrown by `HeliosClient` on upstream failure.
- `src/Support/{Logger,SilentLogger,ConsoleLogger}.php` — minimal logging surface.
- `config/helios-permissions.php` — published config.
- `bin/codegen` — PHP emitter (alternative to the Node emitter).

## Tests

```bash
vendor/bin/phpunit
```

40+ tests across:
- `tests/Unit/RolePermissionsTest.php` — role × perm table; transfer-is-OWNER-only invariant; universal perm invariant.
- `tests/Unit/HeliosClientTest.php` — HMAC signing; 404 → `not_a_member`; non-2xx → `HeliosUnreachableError`; body-parse error → `HeliosUnreachableError`; default `x-source-service`.
- `tests/Unit/InMemoryPermissionCacheTest.php` — `Get`/`Set`/`WriteThrough`/`Invalidate`/`InvalidateTenant`.
- `tests/Unit/PermissionClientTest.php` — cache hit, miss + Helios OK, miss + Helios error + `stale_on_error` true/false, `not_a_member` caches empty, `writeThrough`/`invalidate`/`invalidateTenant`.
- `tests/Unit/FactoryTest.php` — required-options validation, injected-Redis lifecycle.

The Redis cache tests live in the contract repo (they use a real
Predis against a real Redis and are skipped when unreachable) — see
`permission-contract/tests/`.

## Codegen

`src/Role.php`, `src/Permission.php`, and `src/RolePermissions.php`
are generated from
[permission-contract](https://github.com/wazobiatech/permission-contract).
Two ways to regenerate:

```bash
# 1. The PHP-native emitter (no Node required):
php bin/codegen <path-to-permissions.json> src/

# 2. The Node emitter (source of truth, used by the contract repo's CI):
node ../permission-contract/scripts/codegen-php.mjs ../permission-contract/permissions.json src/
```

The CI pipeline fetches `permissions.json` from the public GitHub
mirror at a pinned version, runs the Node emitter, and diffs the
output against the committed files. Drift fails the build.

## Versioning

Semver. The Composer registry (Packagist, or your private mirror)
ingests tagged commits. To publish a new version:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Related

- TypeScript: [`@wazobiatech/helios-permissions`](../helios-permissions)
- Python: [`wazobiatech-helios-permissions`](../helios-permissions-py)
- Go: [`wazobiatech/helios-permissions-go`](../helios-permissions-go)
- Contract: [`wazobiatech/permission-contract`](../permission-contract)
