<?php

declare(strict_types=1);

namespace Wazobia\HeliosPermissions;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\Response;
use Wazobia\HeliosPermissions\Events\HeliosUnreachableError;

/**
 * HeliosClient — HMAC-signed transport to Helios's internal
 * permissions endpoint.
 *
 *   GET /internal/permissions/:userId?tenantId=<uuid>
 *
 * Helios's internal hmac.ts verifier signs:
 *
 *   payload = METHOD + path + timestamp      // METHOD is "GET" (uppercase)
 *   digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
 *   reject  if |now - timestamp| > 300s
 *
 * Path is signed WITHOUT the query string — Helios's verifier signs
 * `req.method + req.path` (Express strips the query string). When
 * Helios's verifier is fixed to canonical, this client updates in
 * lockstep with the TS / Python / Go SDKs.
 *
 * Response shape:
 *
 *   200 → { status: "active", role, permissions, isActive, expiresAt }
 *       | { status: "inactive", reason }
 *   404 → { status: "not_a_member" }
 *
 * Any other non-2xx is a HeliosUnreachableError — the caller
 * (the PermissionClient cache layer) treats that as "stale" and
 * returns the cached value if present.
 */
final class HeliosClient
{
    public const SOURCE_SERVICE_DEFAULT = 'helios-permissions-laravel';

    private const TIMESTAMP_TTL_SECONDS = 300;

    private string $baseUrl;
    private string $signatureSharedSecret;
    private string $sourceService;
    private HttpFactory $http;
    private float $fetchTimeoutSeconds;

    public function __construct(
        string $baseUrl,
        string $signatureSharedSecret,
        ?string $sourceService = null,
        ?HttpFactory $http = null,
        float $fetchTimeoutSeconds = 2.0,
    ) {
        if ($baseUrl === '') {
            throw new \InvalidArgumentException('helios_permissions: HeliosClient.baseUrl is required');
        }
        if ($signatureSharedSecret === '') {
            throw new \InvalidArgumentException('helios_permissions: HeliosClient.signatureSharedSecret is required');
        }
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->signatureSharedSecret = $signatureSharedSecret;
        $this->sourceService = $sourceService ?? self::SOURCE_SERVICE_DEFAULT;
        $this->http = $http ?? new HttpFactory();
        $this->fetchTimeoutSeconds = $fetchTimeoutSeconds;
    }

    /**
     * @return array{status: string, role?: Role, permissions?: list<string>, isActive?: bool, expiresAt?: string, reason?: string}
     *
     * @throws HeliosUnreachableError
     */
    public function fetchUserPermissions(string $userId, string $tenantId): array
    {
        $path = '/internal/permissions/' . $userId;
        $url = $this->baseUrl . $path . '?tenantId=' . $tenantId;
        $timestamp = (string) time();
        $signature = $this->sign('GET', $path, $timestamp);

        try {
            $response = $this->http
                ->withHeaders([
                    'x-source-service' => $this->sourceService,
                    'x-signature'      => $signature,
                    'x-timestamp'      => $timestamp,
                    'Accept'           => 'application/json',
                ])
                ->timeout((int) $this->fetchTimeoutSeconds)
                ->get($url);
        } catch (ConnectionException $e) {
            throw new HeliosUnreachableError(0, 'network', $e);
        } catch (\Throwable $e) {
            throw new HeliosUnreachableError(0, 'request', $e);
        }

        return $this->parseResponse($response);
    }

    /**
     * @return array{status: string, role?: Role, permissions?: list<string>, isActive?: bool, expiresAt?: string, reason?: string}
     *
     * @throws HeliosUnreachableError
     */
    private function parseResponse(Response $response): array
    {
        $status = $response->status();
        if ($status === 404) {
            // Helios returns 404 for not_a_member. Per the SDK
            // contract (TS / Python / Go), treat as a successful
            // resolution with status=not_a_member, not an error.
            return ['status' => 'not_a_member'];
        }
        if ($status < 200 || $status >= 300) {
            $body = $this->safeBody($response);
            throw new HeliosUnreachableError(
                $status,
                'non_2xx',
                new \RuntimeException('body=' . $body),
            );
        }

        $body = $this->safeBody($response);
        $decoded = json_decode($body, true);
        if (!is_array($decoded) || !isset($decoded['status'])) {
            throw new HeliosUnreachableError(
                $status,
                'body_parse',
                new \RuntimeException('body=' . $body),
            );
        }

        $out = ['status' => (string) $decoded['status']];
        if (isset($decoded['role'])) {
            $out['role'] = (string) $decoded['role'];
        }
        if (isset($decoded['permissions']) && is_array($decoded['permissions'])) {
            $out['permissions'] = array_values(array_map('strval', $decoded['permissions']));
        }
        if (isset($decoded['isActive'])) {
            $out['isActive'] = (bool) $decoded['isActive'];
        }
        if (isset($decoded['expiresAt'])) {
            $out['expiresAt'] = (string) $decoded['expiresAt'];
        }
        if (isset($decoded['reason'])) {
            $out['reason'] = (string) $decoded['reason'];
        }
        return $out;
    }

    private function safeBody(Response $response): string
    {
        try {
            return (string) $response->body();
        } catch (\Throwable $e) {
            return '';
        }
    }

    /**
     * Sign a request. Mirrors the TS / Python / Go SDKs and Helios's
     * hmac.ts verifier: METHOD (uppercase) + path (no query) + timestamp.
     */
    public function sign(string $method, string $path, string $timestamp): string
    {
        $payload = strtoupper($method) . $path . $timestamp;
        return hash_hmac('sha256', $payload, $this->signatureSharedSecret);
    }
}
