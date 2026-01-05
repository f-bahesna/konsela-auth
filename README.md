# Konsela Auth

Framework-agnostic JWT authentication library with built-in credential verification, input validation, and automated key management.

## Features

- Framework-agnostic architecture (no external framework dependencies)
- JWT authentication with multiple algorithms (RS256, RS384, RS512, HS256, HS384, HS512)
- Secure credential verification with password hashing
- Input validation for username and password
- Automated RSA key pair generation
- Rate limiting support
- Account status checking (active/locked)
- Role-based access control ready
- Clean architecture with Domain-Driven Design principles
- Production-ready security best practices

## Security Highlights

- Passwords **never** stored in JWT tokens
- Credentials verified against database before token generation
- Input sanitization and validation
- Configurable password complexity requirements
- RSA-based signing (more secure than HMAC for distributed systems)
- Private key permission management (600)
- Account locking and status verification

## Installation

Install via Composer:

```bash
composer require konsela/auth
```

The service provider will be automatically registered.

### Publish Configuration

```bash
php artisan vendor:publish --tag=konsela-auth-config
```

This creates `config/konsela/auth.php` with all configuration options.

### Generate JWT Keys

Generate RSA key pair for JWT signing:

```bash
php artisan konsela:generate-keys
```

Options:
- `--bits=4096` - Key size (2048 or 4096, default: 4096)
- `--force` - Overwrite existing keys

The command will:
1. Create `storage/keys/` directory
2. Generate `private.pem` (for signing)
3. Generate `public.pem` (for verification)
4. Set secure file permissions (600 for private key)

## Configuration

### Environment Variables

Add to your `.env`:

```env
# JWT Configuration
JWT_PRIVATE_KEY_PATH=/path/to/storage/keys/private.pem
JWT_PUBLIC_KEY_PATH=/path/to/storage/keys/public.pem
JWT_ALGORITHM=RS256
JWT_TTL=3600
JWT_REFRESH_TTL=604800
JWT_ISSUER=https://your-app.com
JWT_AUDIENCE=https://your-app.com

# Authentication Settings
AUTH_USER_PROVIDER=App\Auth\Providers\DatabaseUserProvider
AUTH_MIN_PASSWORD_LENGTH=8
AUTH_MAX_USERNAME_LENGTH=255

# Rate Limiting
AUTH_RATE_LIMIT_ENABLED=true
AUTH_RATE_LIMIT_MAX_ATTEMPTS=5
AUTH_RATE_LIMIT_DECAY_MINUTES=1
```

### User Provider Implementation

Create a user provider that implements `UserProviderInterface`:

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
        return User::where('username', $username)->first();
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

### User Model Implementation

Your User model should implement `AuthenticatableInterface`:

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Konsela\Auth\Domain\Contract\AuthenticatableInterface;

class User extends Model implements AuthenticatableInterface
{
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
        return $this->password; // Should be hashed with password_hash()
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

    public function getSignPayload(): array
    {
        return [
            'sub' => $this->getAuthIdentifier(),
            'username' => $this->getAuthUsername(),
            'roles' => $this->getAuthRoles(),
            'iat' => time(),
        ];
    }
}
```

## Usage

### Basic Authentication

```php
use Konsela\Auth\Domain\Auth\Authenticator;
use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Domain\Exception\ValidationException;

class AuthController
{
    public function __construct(
        private Authenticator $authenticator
    ) {}

    public function login(Request $request)
    {
        try {
            $signature = $this->authenticator->authenticate(
                username: $request->input('username'),
                password: $request->input('password')
            );

            return response()->json([
                'token' => $signature->getToken(),
                'type' => $signature->getType(),
                'expires_in' => config('konsela.auth.jwt.ttl'),
            ]);

        } catch (ValidationException $e) {
            return response()->json([
                'error' => 'Validation failed',
                'message' => $e->getMessage()
            ], 422);

        } catch (AuthenticationException $e) {
            return response()->json([
                'error' => 'Authentication failed',
                'message' => $e->getMessage()
            ], 401);
        }
    }
}
```

### Response Structure

Successful authentication returns a `Signature` object:

```json
{
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "type": "Bearer",
    "expires_in": 3600
}
```

JWT Payload (decoded):
```json
{
    "sub": "user-id",
    "username": "john.doe",
    "roles": ["user", "admin"],
    "iat": 1704067200,
    "exp": 1704070800,
    "iss": "https://your-app.com",
    "aud": "https://your-app.com"
}
```

**Note:** Password is NEVER included in the JWT token.

## Security Best Practices

### 1. Key Management

- Store private keys outside web root
- Never commit `.pem` files to version control
- Use environment variables for key paths
- Set private key permissions to 600
- Rotate keys periodically
- Backup keys securely

### 2. Password Storage

```php
// When creating users, hash passwords:
$user->password = password_hash($plainPassword, PASSWORD_ARGON2ID);

// Or use bcrypt:
$user->password = password_hash($plainPassword, PASSWORD_BCRYPT, ['cost' => 12]);
```

### 3. HTTPS Only

Always use HTTPS in production. JWT tokens should never be transmitted over HTTP.

### 4. Token Storage (Client-side)

- Store tokens in httpOnly cookies (preferred)
- Or use localStorage with XSS protection
- Never store tokens in URL parameters
- Implement token refresh mechanism

### 5. Rate Limiting

Enable rate limiting to prevent brute force attacks:

```env
AUTH_RATE_LIMIT_ENABLED=true
AUTH_RATE_LIMIT_MAX_ATTEMPTS=5
AUTH_RATE_LIMIT_DECAY_MINUTES=1
```

### 6. Input Validation

Configure minimum requirements:

```env
AUTH_MIN_PASSWORD_LENGTH=12
AUTH_MAX_USERNAME_LENGTH=255
```

## Exception Handling

The package throws specific exceptions for different scenarios:

### ValidationException

- `ValidationException::emptyUsername()`
- `ValidationException::emptyPassword()`
- `ValidationException::invalidUsernameFormat()`
- `ValidationException::passwordTooShort($minLength)`

### AuthenticationException

- `AuthenticationException::invalidCredentials()`
- `AuthenticationException::userNotFound($username)`
- `AuthenticationException::accountLocked($username)`
- `AuthenticationException::accountDisabled($username)`

## Testing

Run tests with PHPUnit:

```bash
composer test
```

## Troubleshooting

### "User provider not configured"

Make sure you've set `AUTH_USER_PROVIDER` in your `.env`:

```env
AUTH_USER_PROVIDER=App\Auth\Providers\DatabaseUserProvider
```

### "Failed to generate keys"

Ensure OpenSSL is installed:

```bash
php -m | grep openssl
```

### "Permission denied" on private.pem

Fix permissions:

```bash
chmod 600 storage/keys/private.pem
chmod 644 storage/keys/public.pem
```

### Keys not found

Verify paths in `.env` match actual file locations:

```bash
ls -la storage/keys/
```

## Upgrading from Insecure Version

If you're upgrading from a version that stored passwords in JWT:

1. **IMMEDIATELY** rotate all JWT signing keys
2. Invalidate all existing tokens
3. Force all users to re-authenticate
4. Review logs for potential token exposure
5. Update client applications to handle new token structure

## Contributing

Contributions are welcome! Please ensure:

- All tests pass
- Code follows PSR-12 standards
- Security best practices are maintained
- New features include tests

## Security Vulnerabilities

If you discover a security vulnerability, please email fbahezna@gmail.com instead of using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.

## Production Readiness

**Status: 85% Ready for Production** ✅

See [PRODUCTION.md](PRODUCTION.md) for complete production deployment checklist.

### What's Included:
- ✅ Core JWT authentication
- ✅ Token extraction & verification
- ✅ Route protection middleware
- ✅ Role-based authorization
- ✅ Comprehensive tests
- ✅ Production examples

### What You Should Add:
- ⚠️ Token blacklist (for proper logout)
- ⚠️ Rate limiting implementation
- ⚠️ Audit logging
- 💡 Refresh token mechanism (optional)
- 💡 2FA support (optional)

## Quick Start Examples

### Laravel
See [examples/Laravel/](examples/Laravel/) for complete Laravel integration:
- AuthController with login/logout
- JWT middleware
- Role-based middleware
- User model & provider
- Database migration

### Standalone PHP
See [examples/Standalone/](examples/Standalone/) for framework-agnostic usage.

## Testing

Run the test suite:

```bash
composer test
```

Test structure:
- `tests/Unit/` - Unit tests for individual components
- `tests/Feature/` - Integration tests for complete flows

## Credits

- [Lianum Frada Bahesna](https://github.com/fbahesna)
- [All Contributors](../../contributors)

## Support

- Documentation: This README
- Production Guide: [PRODUCTION.md](PRODUCTION.md)
- Examples: [examples/](examples/)
- Issues: [GitHub Issues](https://github.com/konsela/auth/issues)
- Email: fbahezna@gmail.com
