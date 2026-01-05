<?php
declare(strict_types=1);

namespace Konsela\Auth\Domain\Service;

use Konsela\Auth\Domain\Exception\ValidationException;

/**
 * @author frada <fbahezna@gmail.com>
 */
final class CredentialsValidator
{
    public function __construct(
        private int $minPasswordLength = 8,
        private int $maxUsernameLength = 255,
    ) {}

    /**
     * Validate authentication credentials.
     *
     * @throws ValidationException
     */
    public function validate(string $username, string $password): void
    {
        $this->validateUsername($username);
        $this->validatePassword($password);
    }

    /**
     * Validate username format.
     *
     * @throws ValidationException
     */
    private function validateUsername(string $username): void
    {
        if (empty(trim($username))) {
            throw ValidationException::emptyUsername();
        }

        if (strlen($username) > $this->maxUsernameLength) {
            throw ValidationException::invalidUsernameFormat();
        }

        // Basic sanitization check - no control characters
        if (preg_match('/[\x00-\x1F\x7F]/', $username)) {
            throw ValidationException::invalidUsernameFormat();
        }
    }

    /**
     * Validate password requirements.
     *
     * @throws ValidationException
     */
    private function validatePassword(string $password): void
    {
        if (empty($password)) {
            throw ValidationException::emptyPassword();
        }

        if (strlen($password) < $this->minPasswordLength) {
            throw ValidationException::passwordTooShort($this->minPasswordLength);
        }
    }
}
