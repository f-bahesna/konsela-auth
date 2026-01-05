<?php

return [
    /*
    |--------------------------------------------------------------------------
    | JWT Private Key Path
    |--------------------------------------------------------------------------
    |
    | Path to your RSA private key for signing JWT tokens.
    | Generate with: php artisan konsela:generate-keys
    |
    */
    'jwt' => [
        'private_key_path' => env('JWT_PRIVATE_KEY_PATH', storage_path('keys/private.pem')),
        'public_key_path' => env('JWT_PUBLIC_KEY_PATH', storage_path('keys/public.pem')),

        /*
        |--------------------------------------------------------------------------
        | JWT Algorithm
        |--------------------------------------------------------------------------
        |
        | Algorithm used for signing JWT tokens.
        | Supported: RS256, RS384, RS512 (RSA), HS256, HS384, HS512 (HMAC)
        | Recommended: RS256 for production
        |
        */
        'algorithm' => env('JWT_ALGORITHM', 'RS256'),

        /*
        |--------------------------------------------------------------------------
        | JWT Time To Live (TTL)
        |--------------------------------------------------------------------------
        |
        | How long the token will be valid (in seconds).
        | Default: 3600 (1 hour)
        |
        */
        'ttl' => env('JWT_TTL', 3600),

        /*
        |--------------------------------------------------------------------------
        | JWT Refresh TTL
        |--------------------------------------------------------------------------
        |
        | How long the refresh token will be valid (in seconds).
        | Default: 604800 (7 days)
        |
        */
        'refresh_ttl' => env('JWT_REFRESH_TTL', 604800),

        /*
        |--------------------------------------------------------------------------
        | JWT Issuer
        |--------------------------------------------------------------------------
        |
        | The issuer of the token (typically your application URL).
        |
        */
        'issuer' => env('JWT_ISSUER', env('APP_URL', 'http://localhost')),

        /*
        |--------------------------------------------------------------------------
        | JWT Audience
        |--------------------------------------------------------------------------
        |
        | The audience of the token (who the token is intended for).
        |
        */
        'audience' => env('JWT_AUDIENCE', env('APP_URL', 'http://localhost')),
    ],

    /*
    |--------------------------------------------------------------------------
    | User Provider
    |--------------------------------------------------------------------------
    |
    | The user provider implementation to use for authentication.
    | This should be a class that implements UserProviderInterface.
    |
    */
    'user_provider' => env('AUTH_USER_PROVIDER', null),

    /*
    |--------------------------------------------------------------------------
    | Validation Rules
    |--------------------------------------------------------------------------
    |
    | Configure validation rules for authentication.
    |
    */
    'validation' => [
        'min_password_length' => env('AUTH_MIN_PASSWORD_LENGTH', 8),
        'max_username_length' => env('AUTH_MAX_USERNAME_LENGTH', 255),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Configure rate limiting for authentication attempts.
    |
    */
    'rate_limiting' => [
        'enabled' => env('AUTH_RATE_LIMIT_ENABLED', true),
        'max_attempts' => env('AUTH_RATE_LIMIT_MAX_ATTEMPTS', 5),
        'decay_minutes' => env('AUTH_RATE_LIMIT_DECAY_MINUTES', 1),
    ],
];
