# Konsela Auth - Practical Examples

This directory contains practical examples of how to use Konsela Auth in different environments.

## Directory Structure

```
examples/
├── Laravel/                  # Laravel framework integration
│   ├── AuthController.php   # Authentication controller
│   ├── User.php             # User model implementation
│   ├── DatabaseUserProvider.php  # User provider
│   ├── routes.php           # API routes
│   └── migration.php        # Database migration
└── Standalone/              # Pure PHP (no framework)
    └── example.php          # Complete standalone example
```

## Laravel Integration

### 1. Setup Configuration

Add to your `.env` file:

```env
JWT_PRIVATE_KEY_PATH=/path/to/storage/keys/private.pem
JWT_PUBLIC_KEY_PATH=/path/to/storage/keys/public.pem
JWT_ALGORITHM=RS256
JWT_TTL=3600
JWT_ISSUER=https://your-app.com
JWT_AUDIENCE=https://your-app.com
AUTH_USER_PROVIDER=App\Auth\Providers\DatabaseUserProvider
```

### 2. Generate Keys

```bash
php artisan konsela:generate-keys
```

### 3. Publish Configuration

```bash
php artisan vendor:publish --tag=konsela-auth-config
```

### 4. Run Migration

```bash
php artisan migrate
```

### 5. Copy Example Files

Copy the files from `examples/Laravel/` to your Laravel application:

- `AuthController.php` → `app/Http/Controllers/Auth/`
- `User.php` → `app/Models/`
- `DatabaseUserProvider.php` → `app/Auth/Providers/`
- Add routes from `routes.php` to `routes/api.php`

### 6. Test the API

```bash
# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john.doe","password":"SecurePassword123!"}'

# Get user info
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer {your-token}"
```

## Standalone PHP Usage

The standalone example (`Standalone/example.php`) demonstrates how to use Konsela Auth without any framework.

### 1. Generate Keys

```bash
mkdir -p examples/Standalone/keys
openssl genpkey -algorithm RSA -out examples/Standalone/keys/private.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in examples/Standalone/keys/private.pem -out examples/Standalone/keys/public.pem
chmod 600 examples/Standalone/keys/private.pem
```

### 2. Run Example

```bash
php examples/Standalone/example.php
```

Expected output:
```
Attempting to authenticate...
✓ Authentication successful!
Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Type: Bearer
Expires in: 3600 seconds

Verifying token...
✓ Token is valid!
User ID: user-123
Username: john.doe
Roles: user, admin
```

## Key Features Demonstrated

### 1. Basic Authentication
- Username/password validation
- JWT token generation
- Error handling

### 2. Token Management
- Token signing with RSA/HMAC
- Token verification
- Expiration handling

### 3. Security Features
- Password hashing
- Account status checking (active/locked)
- Role-based access control
- Input validation

### 4. Production-Ready Patterns
- Proper error handling
- JSON API responses
- Middleware integration
- Clean architecture

## Common Use Cases

### Create a New User

```php
use App\Models\User;

$user = User::create([
    'username' => 'john.doe',
    'email' => 'john@example.com',
    'password' => password_hash('SecurePassword123!', PASSWORD_BCRYPT),
    'roles' => ['user'],
    'is_active' => true,
    'is_locked' => false,
]);
```

### Check User Roles

```php
// In your controller or middleware
if ($user->hasRole('admin')) {
    // Admin-only logic
}

if ($user->hasAnyRole(['admin', 'moderator'])) {
    // Logic for admin or moderator
}
```

### Custom Claims in Token

```php
// In your User model's getSignPayload method
public function getSignPayload(): array
{
    return [
        'sub' => $this->getAuthIdentifier(),
        'username' => $this->getAuthUsername(),
        'email' => $this->email,
        'roles' => $this->getAuthRoles(),
        'department' => $this->department,  // Custom claim
        'permissions' => $this->permissions, // Custom claim
        'iat' => time(),
    ];
}
```

### Implement Rate Limiting (Laravel)

```php
// In routes/api.php
Route::post('/login', [AuthController::class, 'login'])
    ->middleware('throttle:5,1'); // 5 attempts per minute
```

### Account Locking After Failed Attempts

```php
// In your UserProvider
public function retrieveByCredentials(string $username, string $password): ?AuthenticatableInterface
{
    $user = $this->findByUsername($username);

    if (!$user) {
        return null;
    }

    if (!password_verify($password, $user->getAuthPassword())) {
        // Increment failed attempts
        $user->increment('failed_login_attempts');

        // Lock account after 5 failed attempts
        if ($user->failed_login_attempts >= 5) {
            $user->update([
                'is_locked' => true,
                'locked_until' => now()->addMinutes(30),
            ]);
        }

        return null;
    }

    // Reset failed attempts on successful login
    $user->update([
        'failed_login_attempts' => 0,
        'last_login_at' => now(),
    ]);

    return $user;
}
```

## Troubleshooting

### "Keys not found"
Make sure you've generated the keys and the paths in `.env` are correct:
```bash
ls -la storage/keys/
```

### "Permission denied"
Fix key permissions:
```bash
chmod 600 storage/keys/private.pem
chmod 644 storage/keys/public.pem
```

### "User provider not configured"
Set `AUTH_USER_PROVIDER` in your `.env` file.

## Next Steps

- Implement refresh token logic
- Add token blacklist for logout
- Set up role-based middleware
- Implement two-factor authentication
- Add OAuth/Social login support
