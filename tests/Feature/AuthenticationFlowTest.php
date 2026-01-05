<?php
declare(strict_types=1);

namespace Konsela\Auth\Tests\Feature;

use Konsela\Auth\Domain\Auth\Authenticator;
use Konsela\Auth\Domain\Contract\AuthenticatableInterface;
use Konsela\Auth\Domain\Contract\UserProviderInterface;
use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Domain\Exception\ValidationException;
use Konsela\Auth\Domain\Service\CredentialsValidator;
use Konsela\Auth\Infrastructure\Authentication\AuthenticationManager;
use Konsela\Auth\Infrastructure\Authentication\Authenticator\JwtAuthenticator;
use Konsela\Auth\Infrastructure\Jwt\JwtKeys;
use Konsela\Auth\Infrastructure\Jwt\JwtService;
use Konsela\Auth\Infrastructure\Jwt\JwtSigners;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Token\Parser;
use PHPUnit\Framework\TestCase;

class AuthenticationFlowTest extends TestCase
{
    private Authenticator $authenticator;
    private string $tempDir;
    private MockUserProvider $userProvider;

    protected function setUp(): void
    {
        parent::setUp();

        // Create temporary directory for test keys
        $this->tempDir = sys_get_temp_dir() . '/konsela-auth-test-' . uniqid();
        mkdir($this->tempDir, 0755, true);

        // Generate test RSA keys
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privateKey);
        $publicKey = openssl_pkey_get_details($res);

        file_put_contents($this->tempDir . '/private.pem', $privateKey);
        file_put_contents($this->tempDir . '/public.pem', $publicKey['key']);

        // Setup dependencies
        $signers = new JwtSigners([
            new RsaSha256(),
            new HmacSha256(),
        ]);

        $keys = new JwtKeys([
            'rs' => [
                'private_key' => $this->tempDir . '/private.pem',
                'public_key' => $this->tempDir . '/public.pem',
            ],
            'hs' => [
                'secret_key' => 'test-secret-key',
            ],
        ], $signers);

        $jwtService = new JwtService($signers, $keys);

        $jwtAuthenticator = new JwtAuthenticator(
            jwt: $jwtService,
            defaultAlgo: 'RS256',
            ttl: 3600,
            issuer: 'https://test.example.com',
            audience: 'https://api.test.example.com'
        );

        $authManager = new AuthenticationManager([$jwtAuthenticator]);

        $this->userProvider = new MockUserProvider();

        $validator = new CredentialsValidator(
            minPasswordLength: 8,
            maxUsernameLength: 255
        );

        $this->authenticator = new Authenticator(
            manager: $authManager,
            userProvider: $this->userProvider,
            validator: $validator
        );
    }

    protected function tearDown(): void
    {
        // Clean up
        if (file_exists($this->tempDir . '/private.pem')) {
            unlink($this->tempDir . '/private.pem');
        }
        if (file_exists($this->tempDir . '/public.pem')) {
            unlink($this->tempDir . '/public.pem');
        }
        if (is_dir($this->tempDir)) {
            rmdir($this->tempDir);
        }

        parent::tearDown();
    }

    public function test_successful_authentication_flow(): void
    {
        $signature = $this->authenticator->authenticate('john.doe', 'SecurePassword123!');

        $this->assertNotEmpty($signature->getToken());
        $this->assertEquals('Bearer', $signature->getType());
        $this->assertEquals(3600, $signature->getAttributes()['expires_in']);

        // Verify token contents
        $parser = new Parser(new JoseEncoder());
        $token = $parser->parse($signature->getToken());

        $this->assertEquals('user-123', $token->claims()->get('sub'));
        $this->assertEquals('john.doe', $token->claims()->get('username'));
        $this->assertEquals(['user', 'admin'], $token->claims()->get('roles'));
        $this->assertEquals('https://test.example.com', $token->claims()->get('iss'));
    }

    public function test_authentication_fails_with_invalid_credentials(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Invalid credentials');

        $this->authenticator->authenticate('john.doe', 'WrongPassword');
    }

    public function test_authentication_fails_with_locked_account(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('locked');

        $this->authenticator->authenticate('locked.user', 'SecurePassword123!');
    }

    public function test_authentication_fails_with_inactive_account(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('disabled');

        $this->authenticator->authenticate('inactive.user', 'SecurePassword123!');
    }

    public function test_authentication_fails_with_empty_username(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Username cannot be empty');

        $this->authenticator->authenticate('', 'SecurePassword123!');
    }

    public function test_authentication_fails_with_short_password(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('at least 8 characters');

        $this->authenticator->authenticate('john.doe', 'short');
    }

    public function test_token_contains_all_user_data(): void
    {
        $signature = $this->authenticator->authenticate('john.doe', 'SecurePassword123!');

        $parser = new Parser(new JoseEncoder());
        $token = $parser->parse($signature->getToken());

        // Verify all expected claims are present
        $this->assertTrue($token->claims()->has('sub'));
        $this->assertTrue($token->claims()->has('username'));
        $this->assertTrue($token->claims()->has('roles'));
        $this->assertTrue($token->claims()->has('iat'));
        $this->assertTrue($token->claims()->has('exp'));
        $this->assertTrue($token->claims()->has('iss'));
        $this->assertTrue($token->claims()->has('aud'));

        // Verify password is NOT in token
        $allClaims = $token->claims()->all();
        $this->assertArrayNotHasKey('password', $allClaims);
    }
}

/**
 * Mock User Provider for testing
 */
class MockUserProvider implements UserProviderInterface
{
    public function findById(string|int $id): ?AuthenticatableInterface
    {
        if ($id === 'user-123') {
            return new MockUser(
                id: 'user-123',
                username: 'john.doe',
                password: password_hash('SecurePassword123!', PASSWORD_BCRYPT),
                roles: ['user', 'admin'],
                isActive: true,
                isLocked: false
            );
        }

        return null;
    }

    public function findByUsername(string $username): ?AuthenticatableInterface
    {
        return match ($username) {
            'john.doe' => new MockUser(
                id: 'user-123',
                username: 'john.doe',
                password: password_hash('SecurePassword123!', PASSWORD_BCRYPT),
                roles: ['user', 'admin'],
                isActive: true,
                isLocked: false
            ),
            'locked.user' => new MockUser(
                id: 'user-locked',
                username: 'locked.user',
                password: password_hash('SecurePassword123!', PASSWORD_BCRYPT),
                roles: ['user'],
                isActive: true,
                isLocked: true
            ),
            'inactive.user' => new MockUser(
                id: 'user-inactive',
                username: 'inactive.user',
                password: password_hash('SecurePassword123!', PASSWORD_BCRYPT),
                roles: ['user'],
                isActive: false,
                isLocked: false
            ),
            default => null,
        };
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
 * Mock User for testing
 */
class MockUser implements AuthenticatableInterface
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
