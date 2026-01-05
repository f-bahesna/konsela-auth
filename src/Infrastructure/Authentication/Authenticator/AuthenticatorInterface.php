<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Authentication\Authenticator;

use Konsela\Auth\Domain\Contract\AuthenticatableInterface;
use Konsela\Auth\Infrastructure\Authentication\Model\AuthenticatedUser;
use Konsela\Auth\Shared\Value\Signature;

/**
 * Interface for authentication mechanisms
 *
 * @author frada <fbahezna@gmail.com>
 */
interface AuthenticatorInterface
{
    /**
     * Sign a user and return authentication signature/token
     *
     * @param AuthenticatableInterface $user
     * @param array<string, mixed> $payload Additional payload to include in token
     * @return Signature
     */
    public function sign(AuthenticatableInterface $user, array $payload = []): Signature;

    /**
     * Verify a signature/token and return authenticated user
     *
     * @param Signature $signature
     * @return AuthenticatedUser|null
     */
    public function verify(Signature $signature): ?AuthenticatedUser;

    /**
     * Get authenticator name
     *
     * @return string
     */
    public function getName(): string;
}
