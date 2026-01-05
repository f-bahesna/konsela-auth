<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Authentication;

use Konsela\Auth\Domain\Contract\AuthenticatableInterface;
use Konsela\Auth\Infrastructure\Authentication\Authenticator\AuthenticatorInterface;
use Konsela\Auth\Infrastructure\Authentication\Model\AuthenticatedUser;
use Konsela\Auth\Shared\Value\Signature;
use RuntimeException;

/**
 * Manages multiple authentication mechanisms
 *
 * @author frada <fbahezna@gmail.com>
 */
final class AuthenticationManager
{
    /**
     * @var array<string, AuthenticatorInterface>
     */
    private array $authenticators = [];

    /**
     * @param AuthenticatorInterface[] $authenticators
     */
    public function __construct(array $authenticators = [])
    {
        foreach ($authenticators as $authenticator) {
            $this->add($authenticator);
        }
    }

    public function add(AuthenticatorInterface $authenticator): void
    {
        $this->authenticators[$authenticator->getName()] = $authenticator;
    }

    /**
     * Sign a user with the specified authenticator
     *
     * @param string $authenticatorName
     * @param AuthenticatableInterface $user
     * @param array<string, mixed> $payload
     * @return Signature
     */
    public function sign(string $authenticatorName, AuthenticatableInterface $user, array $payload = []): Signature
    {
        $this->assertAuthenticatorExists($authenticatorName);

        return $this->authenticators[$authenticatorName]->sign($user, $payload);
    }

    /**
     * Verify a signature with the specified authenticator
     *
     * @param string $authenticatorName
     * @param Signature $signature
     * @return AuthenticatedUser|null
     */
    public function verify(string $authenticatorName, Signature $signature): ?AuthenticatedUser
    {
        $this->assertAuthenticatorExists($authenticatorName);

        return $this->authenticators[$authenticatorName]->verify($signature);
    }

    public function has(string $authenticatorName): bool
    {
        return array_key_exists($authenticatorName, $this->authenticators);
    }

    private function assertAuthenticatorExists(string $authenticatorName): void
    {
        if (!$this->has($authenticatorName)) {
            throw new RuntimeException(
                sprintf('Authenticator "%s" not found.', $authenticatorName)
            );
        }
    }
}
