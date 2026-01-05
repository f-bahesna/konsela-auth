<?php
declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Role-based authorization middleware
 *
 * Usage in routes:
 * Route::middleware(['jwt', 'role:admin'])->group(function () {
 *     // Admin-only routes
 * });
 */
class RoleMiddleware
{
    public function handle(Request $request, Closure $next, string ...$roles): Response
    {
        $user = $request->attributes->get('auth_user');

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized',
            ], 401);
        }

        $userRoles = $user->getRoles();

        // Check if user has any of the required roles
        $hasRole = !empty(array_intersect($roles, $userRoles));

        if (!$hasRole) {
            return response()->json([
                'success' => false,
                'message' => 'Forbidden',
                'error' => 'You do not have permission to access this resource',
            ], 403);
        }

        return $next($request);
    }
}
