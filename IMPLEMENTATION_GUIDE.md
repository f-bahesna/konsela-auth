# Implementation Guide

Quick start guide for implementing Konsela Auth in your project.

## Step-by-Step Setup

### Step 1: Install Package

```bash
composer require konsela/auth
```

### Step 2: Publish Configuration

```bash
php artisan vendor:publish --tag=konsela-auth-config
```

### Step 3: Generate JWT Keys

```bash
php artisan konsela:generate-keys
```

This creates:
- `storage/keys/private.pem` (keep secret!)
- `storage/keys/public.pem`

### Step 4: Configure Environment

Add to `.env`:

```env
AUTH_USER_PROVIDER=App\Auth\Providers\DatabaseUserProvider
JWT_PRIVATE_KEY_PATH=/full/path/to/storage/keys/private.pem
JWT_PUBLIC_KEY_PATH=/full/path/to/storage/keys/public.pem
```

### Step 5: Create User Provider

Create `app/Auth/Providers/DatabaseUserProvider.php`:

```php
<?php

namespace App\Auth\Providers;

use Konsela\Auth\Domain\Contract\UserProviderInterface;
use Konsela\Auth\Domain\Contract\AuthenticatableInterface;
use App\Models\User;

class DatabaseUserProvider implements UserProviderInterface
{
    public function findById(string|int $id): ?AuthenticatableInterface
    {
        return User::find($id);
    }

    public function findByUsername(string $username): ?AuthenticatableInterface
    {
        return User::where('username', $username)
            ->orWhere('email', $username)
            ->first();
    }

    public function validateCredentials(string $username, string $password): bool
    {
        $user = $this->findByUsername($username);

        if (!$user) {
            return false;
        }

        return password_verify($password, $user->getAuthPassword());
    }

    public function retrieveByCredentials(string $username, string $password): ?AuthenticatableInterface
    {
        if (!$this->validateCredentials($username, $password)) {
            return null;
        }

        return $this->findByUsername($username);
    }
}
```

### Step 6: Update User Model

Modify `app/Models/User.php`:

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Konsela\Auth\Domain\Contract\AuthenticatableInterface;

class User extends Model implements AuthenticatableInterface
{
    protected $fillable = [
        'username',
        'email',
        'password',
        'roles',
        'is_active',
        'is_locked',
    ];

    protected $hidden = [
        'password',
    ];

    protected $casts = [
        'roles' => 'array',
        'is_active' => 'boolean',
        'is_locked' => 'boolean',
    ];

    // AuthenticatableInterface implementation
    public function getAuthIdentifier(): string|int
    {
        return $this->id;
    }

    public function getAuthUsername(): string
    {
        return $this->username;
    }

    public function getAuthPassword(): string
    {
        return $this->password;
    }

    public function getAuthRoles(): array
    {
        return $this->roles ?? [];
    }

    public function isAccountActive(): bool
    {
        return $this->is_active ?? true;
    }

    public function isAccountLocked(): bool
    {
        return $this->is_locked ?? false;
    }

    // Helper methods
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getAuthRoles(), true);
    }

    public function lockAccount(): void
    {
        $this->is_locked = true;
        $this->save();
    }

    public function unlockAccount(): void
    {
        $this->is_locked = false;
        $this->save();
    }
}
```

### Step 7: Database Migration

Create migration for users table:

```bash
php artisan make:migration create_users_table
```

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('username')->unique();
            $table->string('email')->unique();
            $table->string('password');
            $table->json('roles')->nullable();
            $table->boolean('is_active')->default(true);
            $table->boolean('is_locked')->default(false);
            $table->timestamp('last_login_at')->nullable();
            $table->integer('failed_login_attempts')->default(0);
            $table->timestamps();

            $table->index(['username', 'is_active']);
            $table->index(['email', 'is_active']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
```

Run migration:

```bash
php artisan migrate
```

### Step 8: Create Auth Controller

Create `app/Http/Controllers/AuthController.php`:

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Konsela\Auth\Domain\Auth\Authenticator;
use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Domain\Exception\ValidationException;

class AuthController extends Controller
{
    public function __construct(
        private Authenticator $authenticator
    ) {}

    public function login(Request $request): JsonResponse
    {
        try {
            $signature = $this->authenticator->authenticate(
                username: $request->input('username'),
                password: $request->input('password')
            );

            return response()->json([
                'success' => true,
                'data' => [
                    'token' => $signature->getToken(),
                    'token_type' => $signature->getType(),
                    'expires_in' => config('konsela.auth.jwt.ttl'),
                ],
            ]);

        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'error' => 'validation_error',
                'message' => $e->getMessage(),
            ], 422);

        } catch (AuthenticationException $e) {
            // Log failed attempt
            \Log::warning('Failed login attempt', [
                'username' => $request->input('username'),
                'ip' => $request->ip(),
            ]);

            return response()->json([
                'success' => false,
                'error' => 'authentication_failed',
                'message' => $e->getMessage(),
            ], 401);
        }
    }

    public function logout(Request $request): JsonResponse
    {
        // TODO: Implement token blacklisting if needed
        return response()->json([
            'success' => true,
            'message' => 'Successfully logged out',
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        // TODO: Implement after JWT middleware
        $user = $request->user();

        return response()->json([
            'success' => true,
            'data' => $user,
        ]);
    }
}
```

### Step 9: Add Routes

In `routes/api.php`:

```php
use App\Http\Controllers\AuthController;

Route::prefix('auth')->group(function () {
    Route::post('login', [AuthController::class, 'login']);
    Route::post('logout', [AuthController::class, 'logout'])->middleware('auth:jwt');
    Route::get('me', [AuthController::class, 'me'])->middleware('auth:jwt');
});
```

### Step 10: Create Test User

Create a seeder or run in tinker:

```php
use App\Models\User;

$user = User::create([
    'username' => 'admin',
    'email' => 'admin@example.com',
    'password' => password_hash('SecurePassword123!', PASSWORD_ARGON2ID),
    'roles' => ['admin', 'user'],
    'is_active' => true,
    'is_locked' => false,
]);
```

### Step 11: Test Authentication

```bash
curl -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePassword123!"}'
```

Expected response:

```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
}
```

## Security Checklist

- [ ] Private key has 600 permissions
- [ ] Keys are in `.gitignore`
- [ ] HTTPS enabled in production
- [ ] Rate limiting configured
- [ ] Passwords hashed with Argon2 or Bcrypt
- [ ] Environment variables set correctly
- [ ] Account locking implemented
- [ ] Failed login attempts logged
- [ ] Token refresh mechanism planned
- [ ] CORS configured properly

## Common Issues

### Issue: "User provider not configured"

**Solution:** Set `AUTH_USER_PROVIDER` in `.env` to your provider class.

### Issue: Token verification fails

**Solution:** Ensure public key path is correct and file is readable.

### Issue: "Class not found" for UserProvider

**Solution:** Run `composer dump-autoload` after creating the provider.

### Issue: Authentication always fails

**Solution:** Verify password hashing matches between registration and login.

## Next Steps

1. Implement JWT middleware for protected routes
2. Add token refresh endpoint
3. Implement token blacklisting for logout
4. Add rate limiting middleware
5. Set up monitoring for failed login attempts
6. Implement account recovery flow
7. Add multi-factor authentication (optional)
8. Configure token refresh rotation

## Production Deployment

Before deploying:

1. Change JWT keys (don't use development keys)
2. Use 4096-bit keys in production
3. Enable HTTPS only
4. Configure proper CORS
5. Set up log monitoring
6. Implement token blacklisting
7. Configure session management
8. Set proper cache headers
9. Enable rate limiting
10. Review security headers

## Support

For issues or questions:
- Email: fbahezna@gmail.com
- GitHub Issues: [konsela/auth](https://github.com/konsela/auth/issues)
