<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions\Tests\Unit;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\Request;
use PHPUnit\Framework\TestCase;
use Wazobia\HeliosPermissions\Events\HeliosUnreachableError;
use Wazobia\HeliosPermissions\HeliosClient;

final class HeliosClientTest extends TestCase
{
    private function clientWithFakes(string $secret = 'test', HttpFactory $http = null): HeliosClient
    {
        return new HeliosClient(
            'https://helios.example',
            $secret,
            'helios-permissions-laravel-test',
            $http ?? new HttpFactory(),
        );
    }

    public function test_sign_method_uppercase_path_no_query(): void
    {
        $c = $this->clientWithFakes('topsecret');
        $ts = '1700000000';
        $sig = $c->sign('GET', '/internal/permissions/u', $ts);
        // Independent computation.
        $expected = hash_hmac('sha256', 'GET/internal/permissions/u' . $ts, 'topsecret');
        $this->assertSame($expected, $sig);
        $this->assertSame(64, strlen($sig), 'sha256 hex should be 64 chars');
    }

    public function test_404_is_not_member_resolution(): void
    {
        $http = new HttpFactory();
        $http->fake([
            'helios.example/*' => $http->response(['status' => 'not_a_member'], 404),
        ]);
        $c = $this->clientWithFakes('x', $http);
        $res = $c->fetchUserPermissions('u', 't');
        $this->assertSame('not_a_member', $res['status']);
    }

    public function test_200_active(): void
    {
        $http = new HttpFactory();
        $http->fake([
            'helios.example/*' => $http->response([
                'status' => 'active',
                'role' => 'EDITOR',
                'permissions' => ['athens:project:view', 'athens:project:update'],
                'isActive' => true,
                'expiresAt' => '2027-01-01T00:00:00Z',
            ], 200),
        ]);
        $c = $this->clientWithFakes('x', $http);
        $res = $c->fetchUserPermissions('u', 't');
        $this->assertSame('active', $res['status']);
        $this->assertSame('EDITOR', $res['role']);
        $this->assertSame(['athens:project:view', 'athens:project:update'], $res['permissions']);
        $this->assertTrue($res['isActive']);
        $this->assertSame('2027-01-01T00:00:00Z', $res['expiresAt']);
    }

    public function test_500_throws_unreachable(): void
    {
        $http = new HttpFactory();
        $http->fake([
            'helios.example/*' => $http->response('{"error":"boom"}', 500),
        ]);
        $c = $this->clientWithFakes('x', $http);
        $this->expectException(HeliosUnreachableError::class);
        $c->fetchUserPermissions('u', 't');
    }

    public function test_unparseable_body_throws_unreachable(): void
    {
        $http = new HttpFactory();
        $http->fake([
            'helios.example/*' => $http->response('not-json', 200),
        ]);
        $c = $this->clientWithFakes('x', $http);
        $this->expectException(HeliosUnreachableError::class);
        $c->fetchUserPermissions('u', 't');
    }

    public function test_inactive_response_parses_reason(): void
    {
        $http = new HttpFactory();
        $http->fake([
            'helios.example/*' => $http->response(['status' => 'inactive', 'reason' => 'expired'], 200),
        ]);
        $c = $this->clientWithFakes('x', $http);
        $res = $c->fetchUserPermissions('u', 't');
        $this->assertSame('inactive', $res['status']);
        $this->assertSame('expired', $res['reason']);
    }

    public function test_default_source_service(): void
    {
        $c = new HeliosClient('https://helios.example', 'x');
        $this->assertSame(HeliosClient::SOURCE_SERVICE_DEFAULT, 'helios-permissions-laravel');
    }

    public function test_request_includes_hmac_headers(): void
    {
        $http = new HttpFactory();
        $http->fake([
            'helios.example/*' => $http->response(['status' => 'not_a_member'], 404),
        ]);
        $c = $this->clientWithFakes('topsecret', $http);
        $c->fetchUserPermissions('alice', 'tA');

        $http->assertSent(function (Request $req) {
            $sig = $req->header('x-signature')[0] ?? '';
            $ts = $req->header('x-timestamp')[0] ?? '';
            $source = $req->header('x-source-service')[0] ?? '';
            $expectedSig = hash_hmac('sha256', 'GET/internal/permissions/alice' . $ts, 'topsecret');
            return $sig === $expectedSig
                && $source === 'helios-permissions-laravel-test'
                && $req->method() === 'GET'
                && str_contains((string) $req->url(), 'tenantId=tA');
        });
    }

    public function test_constructor_rejects_empty_base_url(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new HeliosClient('', 'x');
    }

    public function test_constructor_rejects_empty_secret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new HeliosClient('https://helios.example', '');
    }
}
