<?php
declare(strict_types=1);

namespace Konsela\Auth\Tests\Unit\Infrastructure\Jwt;

use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Infrastructure\Jwt\JwtKeys;
use Konsela\Auth\Infrastructure\Jwt\JwtService;
use Konsela\Auth\Infrastructure\Jwt\JwtSigners;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use PHPUnit\Framework\TestCase;

class JwtServiceTest extends TestCase
{
    private JwtService $jwtService;
    private string $tempDir;

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

        // Setup JWT Service
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
                'secret_key' => 'test-secret-key-for-hmac-signing',
            ],
        ], $signers);

        $this->jwtService = new JwtService($signers, $keys);
    }

    protected function tearDown(): void
    {
        // Clean up temporary files
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

    public function test_can_sign_jwt_with_rsa256(): void
    {
        $claims = [
            'sub' => 'user-123',
            'username' => 'john.doe',
            'roles' => ['user', 'admin'],
            'iat' => time(),
        ];

        $token = $this->jwtService->sign('RS256', $claims);

        $this->assertNotEmpty($token->toString());
        $this->assertEquals('user-123', $token->claims()->get('sub'));
        $this->assertEquals('john.doe', $token->claims()->get('username'));
        $this->assertEquals(['user', 'admin'], $token->claims()->get('roles'));
    }

    public function test_can_sign_jwt_with_hmac256(): void
    {
        $claims = [
            'sub' => 'user-456',
            'username' => 'jane.doe',
            'iat' => time(),
        ];

        $token = $this->jwtService->sign('HS256', $claims);

        $this->assertNotEmpty($token->toString());
        $this->assertEquals('user-456', $token->claims()->get('sub'));
        $this->assertEquals('jane.doe', $token->claims()->get('username'));
    }

    public function test_can_verify_valid_token(): void
    {
        $claims = [
            'sub' => 'user-789',
            'username' => 'test.user',
            'iat' => time(),
            'exp' => date('Y-m-d H:i:s', strtotime('+1 hour')),
        ];

        $token = $this->jwtService->sign('RS256', $claims);
        $verified = $this->jwtService->verify($token);

        $this->assertTrue($verified);
    }

    public function test_throws_exception_for_expired_token(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('expired');

        $claims = [
            'sub' => 'user-expired',
            'username' => 'expired.user',
            'iat' => time() - 7200,
            'exp' => date('Y-m-d H:i:s', strtotime('-1 hour')),
        ];

        $token = $this->jwtService->sign('RS256', $claims);
        $this->jwtService->verify($token);
    }

    public function test_token_includes_standard_claims(): void
    {
        $now = time();
        $claims = [
            'sub' => 'user-123',
            'username' => 'john.doe',
            'iat' => $now,
            'exp' => date('Y-m-d H:i:s', strtotime('+1 hour')),
            'iss' => 'https://example.com',
            'aud' => 'https://api.example.com',
        ];

        $token = $this->jwtService->sign('RS256', $claims);

        $this->assertEquals('user-123', $token->claims()->get('sub'));
        $this->assertEquals('https://example.com', $token->claims()->get('iss'));
        $this->assertEquals(['https://api.example.com'], $token->claims()->get('aud'));
    }

    public function test_token_supports_custom_claims(): void
    {
        $claims = [
            'sub' => 'user-123',
            'username' => 'john.doe',
            'email' => 'john@example.com',
            'department' => 'Engineering',
            'custom_field' => 'custom_value',
            'iat' => time(),
        ];

        $token = $this->jwtService->sign('RS256', $claims);

        $this->assertEquals('john@example.com', $token->claims()->get('email'));
        $this->assertEquals('Engineering', $token->claims()->get('department'));
        $this->assertEquals('custom_value', $token->claims()->get('custom_field'));
    }
}
