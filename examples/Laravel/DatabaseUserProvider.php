<?php
declare(strict_types=1);

namespace App\Auth\Providers;

use App\Models\User;
use Konsela\Auth\Domain\Contract\AuthenticatableInterface;
use Konsela\Auth\Domain\Contract\UserProviderInterface;

/**
 * Example User Provider using Laravel's database
 */
class DatabaseUserProvider implements UserProviderInterface
{
    public function findById(string|int $id): ?AuthenticatableInterface
    {
        return User::find($id);
    }

    public function findByUsername(string $username): ?AuthenticatableInterface
    {
        return User::where('username', $username)
            ->orWhere('email', $username)
            ->first();
    }

    public function validateCredentials(string $username, string $password): bool
    {
        $user = $this->findByUsername($username);

        if (!$user) {
            return false;
        }

        return password_verify($password, $user->getAuthPassword());
    }

    public function retrieveByCredentials(string $username, string $password): ?AuthenticatableInterface
    {
        if (!$this->validateCredentials($username, $password)) {
            return null;
        }

        return $this->findByUsername($username);
    }
}
