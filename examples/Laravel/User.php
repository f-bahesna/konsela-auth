<?php
declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Konsela\Auth\Domain\Contract\AuthenticatableInterface;

/**
 * Example User model implementation
 *
 * @property int $id
 * @property string $username
 * @property string $email
 * @property string $password
 * @property array $roles
 * @property bool $is_active
 * @property bool $is_locked
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 */
class User extends Model implements AuthenticatableInterface
{
    use HasFactory;

    protected $fillable = [
        'username',
        'email',
        'password',
        'roles',
        'is_active',
        'is_locked',
    ];

    protected $hidden = [
        'password',
    ];

    protected $casts = [
        'roles' => 'array',
        'is_active' => 'boolean',
        'is_locked' => 'boolean',
    ];

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
        return $this->password;
    }

    public function getAuthRoles(): array
    {
        return $this->roles ?? [];
    }

    public function isAccountActive(): bool
    {
        return $this->is_active ?? true;
    }

    public function isAccountLocked(): bool
    {
        return $this->is_locked ?? false;
    }

    public function getSignPayload(): array
    {
        return [
            'sub' => $this->getAuthIdentifier(),
            'username' => $this->getAuthUsername(),
            'email' => $this->email,
            'roles' => $this->getAuthRoles(),
            'iat' => time(),
        ];
    }

    // Helper methods

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getAuthRoles(), true);
    }

    public function hasAnyRole(array $roles): bool
    {
        return !empty(array_intersect($roles, $this->getAuthRoles()));
    }

    public function hasAllRoles(array $roles): bool
    {
        return empty(array_diff($roles, $this->getAuthRoles()));
    }
}
