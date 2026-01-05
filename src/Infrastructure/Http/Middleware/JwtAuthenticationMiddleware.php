<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Http\Middleware;

use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Infrastructure\Http\JwtGuard;

/**
 * JWT Authentication Middleware (Framework-agnostic)
 *
 * Adapt this for your framework (Laravel, Symfony, etc.)
 *
 * @author frada <fbahezna@gmail.com>
 */
final class JwtAuthenticationMiddleware
{
    public function __construct(
        private readonly JwtGuard $guard
    ) {}

    /**
     * Handle the request
     *
     * This is a framework-agnostic implementation.
     * Adapt it to your framework's middleware signature.
     *
     * @param array $headers Request headers
     * @param array $queryParams Query parameters
     * @param array $cookies Cookies
     * @param callable $next Next middleware/handler
     * @return mixed
     */
    public function handle(
        array $headers,
        array $queryParams,
        array $cookies,
        callable $next
    ): mixed {
        try {
            // Authenticate the request
            $user = $this->guard->authenticate($headers, $queryParams, $cookies);

            // Store user in request context (framework-specific)
            // For Laravel: $request->setUserResolver(fn() => $user);
            // For Symfony: Add to request attributes

            // Continue to next middleware
            return $next($user);

        } catch (AuthenticationException $e) {
            // Return unauthorized response (framework-specific)
            // For Laravel: return response()->json(['error' => 'Unauthorized'], 401);
            // For Symfony: throw new UnauthorizedHttpException('Bearer');

            throw $e; // Rethrow for framework to handle
        }
    }

    /**
     * Optional: Allow certain routes without authentication
     */
    public function shouldSkip(string $path): bool
    {
        $publicRoutes = [
            '/api/auth/login',
            '/api/auth/register',
            '/health',
        ];

        foreach ($publicRoutes as $route) {
            if (str_starts_with($path, $route)) {
                return true;
            }
        }

        return false;
    }
}
