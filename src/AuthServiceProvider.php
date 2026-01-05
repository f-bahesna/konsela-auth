<?php
declare(strict_types=1);

namespace Konsela\Auth;

use Illuminate\Support\ServiceProvider;
use Konsela\Auth\Console\GenerateKeysCommand;
use Konsela\Auth\Domain\Auth\Authenticator;
use Konsela\Auth\Domain\Contract\UserProviderInterface;
use Konsela\Auth\Domain\Service\CredentialsValidator;
use Konsela\Auth\Infrastructure\Authentication\AuthenticationManager;
use Konsela\Auth\Infrastructure\Authentication\Authenticator\JwtAuthenticator;
use Konsela\Auth\Infrastructure\Jwt\JwtKeys;
use Konsela\Auth\Infrastructure\Jwt\JwtService;
use Konsela\Auth\Infrastructure\Jwt\JwtSigners;
use Konsela\Auth\Infrastructure\Http\TokenExtractor;
use Konsela\Auth\Infrastructure\Http\JwtGuard;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HmacSha384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HmacSha512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RsaSha512;

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

        // Register JWT Signers
        $this->app->singleton(JwtSigners::class, function ($app) {
            return new JwtSigners([
                new RsaSha256(),
                new RsaSha384(),
                new RsaSha512(),
                new HmacSha256(),
                new HmacSha384(),
                new HmacSha512(),
            ]);
        });

        // Register JWT Keys
        $this->app->singleton(JwtKeys::class, function ($app) {
            $config = $app['config']->get('konsela.auth.jwt', []);

            $keys = [
                'rs' => [
                    'private_key' => $config['private_key_path'] ?? storage_path('keys/private.pem'),
                    'public_key' => $config['public_key_path'] ?? storage_path('keys/public.pem'),
                    'passphrase' => $config['passphrase'] ?? '',
                ],
                'hs' => [
                    'secret_key' => $config['secret_key'] ?? env('JWT_SECRET_KEY', ''),
                ],
            ];

            return new JwtKeys($keys, $app->make(JwtSigners::class));
        });

        // Register JWT Service
        $this->app->singleton(JwtService::class, function ($app) {
            return new JwtService(
                $app->make(JwtSigners::class),
                $app->make(JwtKeys::class)
            );
        });

        // Register JWT Authenticator
        $this->app->singleton(JwtAuthenticator::class, function ($app) {
            $config = $app['config']->get('konsela.auth.jwt', []);

            return new JwtAuthenticator(
                jwt: $app->make(JwtService::class),
                defaultAlgo: $config['algorithm'] ?? 'RS256',
                ttl: $config['ttl'] ?? 3600,
                issuer: $config['issuer'] ?? null,
                audience: $config['audience'] ?? null
            );
        });

        // Register Authentication Manager
        $this->app->singleton(AuthenticationManager::class, function ($app) {
            return new AuthenticationManager([
                $app->make(JwtAuthenticator::class),
            ]);
        });

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
                manager: $app->make(AuthenticationManager::class),
                userProvider: $app->make(UserProviderInterface::class),
                validator: $app->make(CredentialsValidator::class),
            );
        });

        // Register Token Extractor
        $this->app->singleton(TokenExtractor::class, function ($app) {
            return new TokenExtractor();
        });

        // Register JWT Guard
        $this->app->singleton(JwtGuard::class, function ($app) {
            return new JwtGuard(
                authManager: $app->make(AuthenticationManager::class),
                tokenExtractor: $app->make(TokenExtractor::class)
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
