<?php
declare(strict_types=1);

/**
 * Standalone PHP Example (No Framework Required)
 *
 * This demonstrates how to use Konsela Auth without any framework
 */

require __DIR__ . '/../../vendor/autoload.php';

use Konsela\Auth\Domain\Auth\Authenticator;
use Konsela\Auth\Domain\Contract\AuthenticatableInterface;
use Konsela\Auth\Domain\Contract\UserProviderInterface;
use Konsela\Auth\Domain\Service\CredentialsValidator;
use Konsela\Auth\Infrastructure\Authentication\AuthenticationManager;
use Konsela\Auth\Infrastructure\Authentication\Authenticator\JwtAuthenticator;
use Konsela\Auth\Infrastructure\Jwt\JwtKeys;
use Konsela\Auth\Infrastructure\Jwt\JwtService;
use Konsela\Auth\Infrastructure\Jwt\JwtSigners;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;

// 1. Configure JWT Signers
$signers = new JwtSigners([
    new RsaSha256(),
    new HmacSha256(),
]);

// 2. Configure JWT Keys
$keys = new JwtKeys([
    'rs' => [
        'private_key' => __DIR__ . '/keys/private.pem',
        'public_key' => __DIR__ . '/keys/public.pem',
        'passphrase' => '', // Add if your key has a passphrase
    ],
    'hs' => [
        'secret_key' => 'your-secret-key-here-change-in-production',
    ],
], $signers);

// 3. Create JWT Service
$jwtService = new JwtService($signers, $keys);

// 4. Create JWT Authenticator
$jwtAuthenticator = new JwtAuthenticator(
    jwt: $jwtService,
    defaultAlgo: 'RS256',
    ttl: 3600, // 1 hour
    issuer: 'https://your-app.com',
    audience: 'https://your-app.com'
);

// 5. Create Authentication Manager
$authManager = new AuthenticationManager([
    $jwtAuthenticator,
]);

// 6. Create User Provider (implement your own)
$userProvider = new SimpleUserProvider();

// 7. Create Credentials Validator
$validator = new CredentialsValidator(
    minPasswordLength: 8,
    maxUsernameLength: 255
);

// 8. Create Main Authenticator
$authenticator = new Authenticator(
    manager: $authManager,
    userProvider: $userProvider,
    validator: $validator
);

// Example 1: Login
try {
    echo "Attempting to authenticate...\n";

    $signature = $authenticator->authenticate(
        username: 'john.doe',
        password: 'SecurePassword123!'
    );

    echo "✓ Authentication successful!\n";
    echo "Token: " . $signature->getToken() . "\n";
    echo "Type: " . $signature->getType() . "\n";
    echo "Expires in: " . $signature->getAttributes()['expires_in'] . " seconds\n\n";

    // Store this token and send it to the client
    $accessToken = $signature->getToken();

} catch (\Konsela\Auth\Domain\Exception\ValidationException $e) {
    echo "✗ Validation error: " . $e->getMessage() . "\n";
} catch (\Konsela\Auth\Domain\Exception\AuthenticationException $e) {
    echo "✗ Authentication error: " . $e->getMessage() . "\n";
}

// Example 2: Verify Token
if (isset($accessToken)) {
    echo "Verifying token...\n";

    try {
        $parser = new \Lcobucci\JWT\Encoding\JoseEncoder();
        $tokenParser = new \Lcobucci\JWT\Token\Parser($parser);
        $token = $tokenParser->parse($accessToken);

        $verified = $jwtService->verify($token);

        if ($verified) {
            echo "✓ Token is valid!\n";
            echo "User ID: " . $token->claims()->get('sub') . "\n";
            echo "Username: " . $token->claims()->get('username') . "\n";
            echo "Roles: " . implode(', ', $token->claims()->get('roles')) . "\n";
        }
    } catch (\Throwable $e) {
        echo "✗ Token verification failed: " . $e->getMessage() . "\n";
    }
}

/**
 * Simple User Provider Implementation
 * Replace this with your actual database or storage implementation
 */
class SimpleUserProvider implements UserProviderInterface
{
    private array $users = [];

    public function __construct()
    {
        // Simulated user database
        $this->users = [
            'john.doe' => new SimpleUser(
                id: 'user-123',
                username: 'john.doe',
                password: password_hash('SecurePassword123!', PASSWORD_BCRYPT),
                roles: ['user', 'admin'],
                isActive: true,
                isLocked: false
            ),
        ];
    }

    public function findById(string|int $id): ?AuthenticatableInterface
    {
        foreach ($this->users as $user) {
            if ($user->getAuthIdentifier() === $id) {
                return $user;
            }
        }
        return null;
    }

    public function findByUsername(string $username): ?AuthenticatableInterface
    {
        return $this->users[$username] ?? null;
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

/**
 * Simple User Implementation
 */
class SimpleUser implements AuthenticatableInterface
{
    public function __construct(
        private string|int $id,
        private string $username,
        private string $password,
        private array $roles = [],
        private bool $isActive = true,
        private bool $isLocked = false
    ) {}

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
        return $this->roles;
    }

    public function isAccountActive(): bool
    {
        return $this->isActive;
    }

    public function isAccountLocked(): bool
    {
        return $this->isLocked;
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
