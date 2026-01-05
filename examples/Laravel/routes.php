<?php

use App\Http\Controllers\Auth\AuthController;
use Illuminate\Support\Facades\Route;

/**
 * Example routes for Laravel application
 *
 * Add these to your routes/api.php file
 */

Route::prefix('auth')->group(function () {
    // Public routes (no authentication required)
    Route::post('/login', [AuthController::class, 'login'])
        ->name('auth.login');

    // Protected routes (authentication required)
    Route::middleware('auth:jwt')->group(function () {
        Route::get('/me', [AuthController::class, 'me'])
            ->name('auth.me');

        Route::post('/logout', [AuthController::class, 'logout'])
            ->name('auth.logout');

        Route::post('/refresh', [AuthController::class, 'refresh'])
            ->name('auth.refresh');
    });
});

/**
 * Example protected API routes
 */
Route::middleware('auth:jwt')->group(function () {
    Route::get('/users', function () {
        return response()->json(['users' => []]);
    });

    Route::prefix('admin')->middleware('role:admin')->group(function () {
        Route::get('/dashboard', function () {
            return response()->json(['message' => 'Admin dashboard']);
        });
    });
});
