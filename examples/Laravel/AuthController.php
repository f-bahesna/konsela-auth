<?php
declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Konsela\Auth\Domain\Auth\Authenticator;
use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Domain\Exception\ValidationException;

/**
 * Example Authentication Controller for Laravel
 *
 * This demonstrates how to integrate Konsela Auth into a Laravel application
 */
class AuthController extends Controller
{
    public function __construct(
        private readonly Authenticator $authenticator
    ) {}

    /**
     * Handle login request
     *
     * POST /api/auth/login
     * Body: { "username": "john.doe", "password": "SecurePassword123!" }
     */
    public function login(Request $request): JsonResponse
    {
        try {
            $signature = $this->authenticator->authenticate(
                username: $request->input('username'),
                password: $request->input('password')
            );

            return response()->json([
                'success' => true,
                'message' => 'Authentication successful',
                'data' => [
                    'access_token' => $signature->getToken(),
                    'token_type' => $signature->getType(),
                    'expires_in' => $signature->getAttributes()['expires_in'] ?? 3600,
                ],
            ], 200);

        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => [
                    'message' => $e->getMessage(),
                ],
            ], 422);

        } catch (AuthenticationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Authentication failed',
                'errors' => [
                    'message' => $e->getMessage(),
                ],
            ], 401);

        } catch (\Throwable $e) {
            return response()->json([
                'success' => false,
                'message' => 'An unexpected error occurred',
                'errors' => [
                    'message' => config('app.debug') ? $e->getMessage() : 'Internal server error',
                ],
            ], 500);
        }
    }

    /**
     * Get authenticated user information
     *
     * GET /api/auth/me
     * Headers: Authorization: Bearer {token}
     */
    public function me(Request $request): JsonResponse
    {
        // This assumes you have JWT authentication middleware
        $user = $request->user();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized',
            ], 401);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $user->getAuthIdentifier(),
                'username' => $user->getAuthUsername(),
                'roles' => $user->getAuthRoles(),
            ],
        ]);
    }

    /**
     * Handle logout request
     *
     * POST /api/auth/logout
     * Headers: Authorization: Bearer {token}
     *
     * Note: With JWT, logout is typically handled client-side by removing the token.
     * For server-side logout, implement a token blacklist.
     */
    public function logout(Request $request): JsonResponse
    {
        // Token blacklist implementation would go here
        // For now, we just return success and rely on client to remove token

        return response()->json([
            'success' => true,
            'message' => 'Logged out successfully',
        ]);
    }

    /**
     * Refresh token
     *
     * POST /api/auth/refresh
     * Headers: Authorization: Bearer {token}
     *
     * This would generate a new token using the refresh token mechanism
     */
    public function refresh(Request $request): JsonResponse
    {
        try {
            $user = $request->user();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Unauthorized',
                ], 401);
            }

            // Re-authenticate the user to generate a new token
            $signature = $this->authenticator->authenticate(
                username: $user->getAuthUsername(),
                password: '' // Note: This needs to be implemented with refresh token logic
            );

            return response()->json([
                'success' => true,
                'message' => 'Token refreshed successfully',
                'data' => [
                    'access_token' => $signature->getToken(),
                    'token_type' => $signature->getType(),
                    'expires_in' => $signature->getAttributes()['expires_in'] ?? 3600,
                ],
            ]);

        } catch (\Throwable $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to refresh token',
            ], 401);
        }
    }
}
