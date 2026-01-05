<?php
declare(strict_types=1);

namespace Konsela\Auth\Domain\Contract;

/**
 * Interface for authenticatable user entities.
 *
 * @author frada <fbahezna@gmail.com>
 */
interface AuthenticatableInterface
{
    /**
     * Get the unique identifier for the user.
     */
    public function getAuthIdentifier(): string|int;

    /**
     * Get the username for the user.
     */
    public function getAuthUsername(): string;

    /**
     * Get the hashed password for the user.
     */
    public function getAuthPassword(): string;

    /**
     * Get the roles assigned to the user.
     *
     * @return array<string>
     */
    public function getAuthRoles(): array;

    /**
     * Check if the account is active.
     */
    public function isAccountActive(): bool;

    /**
     * Check if the account is locked.
     */
    public function isAccountLocked(): bool;
}
