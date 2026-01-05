<?php
declare(strict_types=1);

namespace Konsela\Auth\Domain\Auth;

use Pandawa\Module\Api\Security\Authentication\AuthenticationManager;
use Konsela\Auth\Domain\Contract\UserProviderInterface;
use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Domain\Identity\SignableIdentity;
use Konsela\Auth\Domain\Service\CredentialsValidator;
use Konsela\Auth\Shared\Value\Signature;
use RuntimeException;

/**
 * @author frada <fbahezna@gmail.com>
 */
final class Authenticator
{
    public function __construct(
        private AuthenticationManager $manager,
        private UserProviderInterface $userProvider,
        private CredentialsValidator $validator,
        private ?string $type = null,
    ) {}

    /**
     * Authenticate user with username and password.
     *
     * @throws AuthenticationException
     * @throws \Konsela\Auth\Domain\Exception\ValidationException
     */
    public function authenticate(string $username, string $password): Signature
    {
        if (!$this->type) {
            return $this->basicLogin($username, $password);
        }

        return $this->socialLogin();
    }

    /**
     * Perform basic authentication with credentials verification.
     *
     * @throws AuthenticationException
     * @throws \Konsela\Auth\Domain\Exception\ValidationException
     */
    private function basicLogin(string $username, string $password): Signature
    {
        // Validate input format
        $this->validator->validate($username, $password);

        // Retrieve and verify user
        $user = $this->userProvider->retrieveByCredentials($username, $password);

        if (!$user) {
            throw AuthenticationException::invalidCredentials();
        }

        // Check account status
        if ($user->isAccountLocked()) {
            throw AuthenticationException::accountLocked($username);
        }

        if (!$user->isAccountActive()) {
            throw AuthenticationException::accountDisabled($username);
        }

        // Create identity for JWT signing (without password)
        $identity = new SignableIdentity(
            id: $user->getAuthIdentifier(),
            username: $user->getAuthUsername(),
            roles: $user->getAuthRoles(),
        );

        // Sign and return token
        $signature = $this->manager->sign('jwt', $identity);

        return new Signature(
            $signature->getCredentials(),
            'Bearer',
            $signature->getAttributes()
        );
    }

    /**
     * Perform social authentication.
     *
     * @throws RuntimeException
     */
    private function socialLogin(): Signature
    {
        //TODO: Implement social login
        throw new RuntimeException('Social login not implemented yet.');
    }
}
