<?php
declare(strict_types=1);

namespace Konsela\Auth\Domain\Identity;

use Pandawa\Module\Api\Security\Contract\SignableUserInterface;

/**
 * @author frada <fbahezna@gmail.com>
 */
final class SignableIdentity implements SignableUserInterface
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
}