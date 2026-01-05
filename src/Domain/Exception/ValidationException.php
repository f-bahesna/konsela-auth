<?php
declare(strict_types=1);

namespace Konsela\Auth\Domain\Exception;

use InvalidArgumentException;

/**
 * @author frada <fbahezna@gmail.com>
 */
class ValidationException extends InvalidArgumentException
{
    public static function emptyUsername(): self
    {
        return new self('Username cannot be empty.');
    }

    public static function emptyPassword(): self
    {
        return new self('Password cannot be empty.');
    }

    public static function invalidUsernameFormat(): self
    {
        return new self('Username format is invalid.');
    }

    public static function passwordTooShort(int $minLength): self
    {
        return new self("Password must be at least {$minLength} characters long.");
    }
}
