<?php
declare(strict_types=1);

namespace Konsela\Auth\Domain\Contract;

/**
 * Interface for user providers that retrieve user data.
 *
 * @author frada <fbahezna@gmail.com>
 */
interface UserProviderInterface
{
    /**
     * Retrieve a user by their unique identifier.
     */
    public function findById(string|int $id): ?AuthenticatableInterface;

    /**
     * Retrieve a user by their username.
     */
    public function findByUsername(string $username): ?AuthenticatableInterface;

    /**
     * Validate a user's credentials.
     *
     * @param string $username
     * @param string $password Plain text password
     * @return bool
     */
    public function validateCredentials(string $username, string $password): bool;

    /**
     * Retrieve a user by credentials.
     *
     * @param string $username
     * @param string $password Plain text password
     * @return AuthenticatableInterface|null
     */
    public function retrieveByCredentials(string $username, string $password): ?AuthenticatableInterface;
}
