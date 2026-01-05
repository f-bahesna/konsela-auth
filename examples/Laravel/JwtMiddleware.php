<?php
declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Infrastructure\Http\JwtGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel JWT Middleware Implementation
 */
class JwtMiddleware
{
    public function __construct(
        private readonly JwtGuard $guard
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        try {
            // Extract headers, query params, and cookies
            $headers = $request->headers->all();
            $queryParams = $request->query->all();
            $cookies = $request->cookies->all();

            // Authenticate
            $user = $this->guard->authenticate($headers, $queryParams, $cookies);

            // Store authenticated user in request
            $request->attributes->set('auth_user', $user);

            // Also make it available via auth() helper (optional)
            $request->setUserResolver(function () use ($user) {
                return $user;
            });

            return $next($request);

        } catch (AuthenticationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized',
                'error' => $e->getMessage(),
            ], 401);
        } catch (\Throwable $e) {
            return response()->json([
                'success' => false,
                'message' => 'Authentication error',
                'error' => config('app.debug') ? $e->getMessage() : 'Internal server error',
            ], 500);
        }
    }
}
