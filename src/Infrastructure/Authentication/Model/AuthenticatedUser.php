<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Authentication\Model;

/**
 * Represents an authenticated user from a verified token
 *
 * @author frada <fbahezna@gmail.com>
 */
final class AuthenticatedUser
{
    private string $identifier;
    private array $claims;

    /**
     * @param string $identifier User identifier (typically from 'sub' claim)
     * @param array<string, mixed> $claims All JWT claims
     */
    public function __construct(string $identifier, array $claims = [])
    {
        $this->identifier = $identifier;
        $this->claims = $claims;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function getClaim(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }

    public function getUsername(): ?string
    {
        return $this->getClaim('username');
    }

    public function getRoles(): array
    {
        return $this->getClaim('roles', []);
    }
}
