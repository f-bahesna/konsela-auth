<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Http;

use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Infrastructure\Authentication\AuthenticationManager;
use Konsela\Auth\Infrastructure\Authentication\Model\AuthenticatedUser;
use Konsela\Auth\Shared\Value\Signature;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;

/**
 * JWT Guard for request authentication
 *
 * @author frada <fbahezna@gmail.com>
 */
final class JwtGuard
{
    private ?AuthenticatedUser $user = null;

    public function __construct(
        private readonly AuthenticationManager $authManager,
        private readonly TokenExtractor $tokenExtractor
    ) {}

    /**
     * Authenticate request and return authenticated user
     *
     * @param array $headers HTTP headers
     * @param array $queryParams Query parameters
     * @param array $cookies Cookies
     * @return AuthenticatedUser
     * @throws AuthenticationException
     */
    public function authenticate(
        array $headers,
        array $queryParams = [],
        array $cookies = []
    ): AuthenticatedUser {
        // Check if already authenticated
        if ($this->user !== null) {
            return $this->user;
        }

        // Extract token
        $token = $this->tokenExtractor->extract($headers, $queryParams, $cookies);

        if (!$token) {
            throw AuthenticationException::invalidToken('No authentication token provided');
        }

        // Verify token
        $signature = new Signature($token, 'Bearer');
        $user = $this->authManager->verify('jwt', $signature);

        if (!$user) {
            throw AuthenticationException::invalidToken('Invalid or expired token');
        }

        $this->user = $user;

        return $user;
    }

    /**
     * Check if request is authenticated
     */
    public function check(array $headers, array $queryParams = [], array $cookies = []): bool
    {
        try {
            $this->authenticate($headers, $queryParams, $cookies);
            return true;
        } catch (AuthenticationException) {
            return false;
        }
    }

    /**
     * Get authenticated user (null if not authenticated)
     */
    public function user(): ?AuthenticatedUser
    {
        return $this->user;
    }

    /**
     * Verify a specific token string
     *
     * @throws AuthenticationException
     */
    public function verifyToken(string $token): AuthenticatedUser
    {
        $signature = new Signature($token, 'Bearer');
        $user = $this->authManager->verify('jwt', $signature);

        if (!$user) {
            throw AuthenticationException::invalidToken('Invalid or expired token');
        }

        return $user;
    }

    /**
     * Parse token without verification (use with caution)
     */
    public function parseToken(string $token): array
    {
        try {
            $parser = new Parser(new JoseEncoder());
            $parsed = $parser->parse($token);

            return $parsed->claims()->all();
        } catch (\Throwable $e) {
            throw AuthenticationException::invalidToken('Failed to parse token: ' . $e->getMessage());
        }
    }
}
