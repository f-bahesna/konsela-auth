<?php
declare(strict_types=1);

namespace Konsela\Auth\Domain\Exception;

use RuntimeException;

/**
 * @author frada <fbahezna@gmail.com>
 */
class AuthenticationException extends RuntimeException
{
    public static function invalidCredentials(): self
    {
        return new self('Invalid credentials provided.');
    }

    public static function userNotFound(string $username): self
    {
        return new self("User with username '{$username}' not found.");
    }

    public static function accountLocked(string $username): self
    {
        return new self("Account '{$username}' is locked.");
    }

    public static function accountDisabled(string $username): self
    {
        return new self("Account '{$username}' is disabled.");
    }
}
