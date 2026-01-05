<?php
declare(strict_types=1);

namespace Konsela\Auth\Domain\Identity;

use Konsela\Auth\Domain\Contract\AuthenticatableInterface;

/**
 * Represents a signable user identity for JWT token generation
 *
 * @author frada <fbahezna@gmail.com>
 */
final class SignableIdentity implements AuthenticatableInterface
{
    public function __construct(
        private string|int $id,
        private string $username,
        private array $roles = [],
        private array $additionalClaims = [],
    ){}

    public function getSignPayload(): array
    {
        return array_merge(
            [
                'sub' => $this->id, // Subject (user ID)
                'username' => $this->username,
                'roles' => $this->roles,
                'iat' => time(), // Issued at
            ],
            $this->additionalClaims
        );
    }

    public function getId(): string|int
    {
        return $this->id;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    // AuthenticatableInterface implementation
    public function getAuthIdentifier(): string|int
    {
        return $this->id;
    }

    public function getAuthUsername(): string
    {
        return $this->username;
    }

    public function getAuthPassword(): string
    {
        // Not needed for signing, only for authentication
        return '';
    }

    public function getAuthRoles(): array
    {
        return $this->roles;
    }

    public function isAccountActive(): bool
    {
        return true;
    }

    public function isAccountLocked(): bool
    {
        return false;
    }
}