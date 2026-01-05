<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Http;

/**
 * Extracts JWT token from HTTP requests
 *
 * @author frada <fbahezna@gmail.com>
 */
final class TokenExtractor
{
    /**
     * Extract token from Authorization header
     *
     * Supports formats:
     * - Authorization: Bearer {token}
     * - Authorization: {token}
     */
    public function extractFromHeader(array $headers): ?string
    {
        $authorization = $this->getAuthorizationHeader($headers);

        if (!$authorization) {
            return null;
        }

        // Remove "Bearer " prefix if present
        if (stripos($authorization, 'Bearer ') === 0) {
            return trim(substr($authorization, 7));
        }

        return trim($authorization);
    }

    /**
     * Extract token from query parameter
     *
     * Example: ?token={token}
     */
    public function extractFromQuery(array $queryParams, string $paramName = 'token'): ?string
    {
        return $queryParams[$paramName] ?? null;
    }

    /**
     * Extract token from cookie
     */
    public function extractFromCookie(array $cookies, string $cookieName = 'access_token'): ?string
    {
        return $cookies[$cookieName] ?? null;
    }

    /**
     * Extract token from multiple sources (tries in order)
     *
     * @param array $headers HTTP headers
     * @param array $queryParams Query parameters
     * @param array $cookies Cookies
     */
    public function extract(array $headers, array $queryParams = [], array $cookies = []): ?string
    {
        // Try Authorization header first (most secure and standard)
        $token = $this->extractFromHeader($headers);
        if ($token) {
            return $token;
        }

        // Try cookie (good for web apps)
        $token = $this->extractFromCookie($cookies);
        if ($token) {
            return $token;
        }

        // Try query parameter (least secure, only for specific use cases)
        $token = $this->extractFromQuery($queryParams);
        if ($token) {
            return $token;
        }

        return null;
    }

    private function getAuthorizationHeader(array $headers): ?string
    {
        // Handle different header key formats
        $authHeaders = [
            'Authorization',
            'authorization',
            'HTTP_AUTHORIZATION',
        ];

        foreach ($authHeaders as $key) {
            if (isset($headers[$key])) {
                return $headers[$key];
            }
        }

        return null;
    }
}
