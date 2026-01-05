<?php
declare(strict_types=1);

namespace Konsela\Auth;

use Illuminate\Support\ServiceProvider;
use Konsela\Auth\Console\GenerateKeysCommand;
use Konsela\Auth\Domain\Auth\Authenticator;
use Konsela\Auth\Domain\Contract\UserProviderInterface;
use Konsela\Auth\Domain\Service\CredentialsValidator;

/**
 * Service Provider for Konsela Auth Package
 *
 * @author frada <fbahezna@gmail.com>
 */
class AuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Merge configuration
        $this->mergeConfigFrom(
            __DIR__ . '/../config/auth.php',
            'konsela.auth'
        );

        // Register CredentialsValidator
        $this->app->singleton(CredentialsValidator::class, function ($app) {
            $config = $app['config']->get('konsela.auth.validation', []);

            return new CredentialsValidator(
                minPasswordLength: $config['min_password_length'] ?? 8,
                maxUsernameLength: $config['max_username_length'] ?? 255,
            );
        });

        // Register UserProvider - must be provided by the application
        $this->app->singleton(UserProviderInterface::class, function ($app) {
            $providerClass = $app['config']->get('konsela.auth.user_provider');

            if (!$providerClass) {
                throw new \RuntimeException(
                    'You must configure a user provider in config/konsela/auth.php. ' .
                    'Set the "user_provider" key to your UserProviderInterface implementation.'
                );
            }

            if (!class_exists($providerClass)) {
                throw new \RuntimeException(
                    "User provider class '{$providerClass}' not found."
                );
            }

            $provider = $app->make($providerClass);

            if (!$provider instanceof UserProviderInterface) {
                throw new \RuntimeException(
                    "User provider must implement " . UserProviderInterface::class
                );
            }

            return $provider;
        });

        // Register Authenticator
        $this->app->singleton(Authenticator::class, function ($app) {
            return new Authenticator(
                manager: $app->make(\Pandawa\Module\Api\Security\Authentication\AuthenticationManager::class),
                userProvider: $app->make(UserProviderInterface::class),
                validator: $app->make(CredentialsValidator::class),
            );
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Publish configuration
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/auth.php' => config_path('konsela/auth.php'),
            ], 'konsela-auth-config');

            // Register commands
            $this->commands([
                GenerateKeysCommand::class,
            ]);
        }
    }
}
