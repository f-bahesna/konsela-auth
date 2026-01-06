<?php

return [
    /*
    |--------------------------------------------------------------------------
    | JWT Private Key Path
    |--------------------------------------------------------------------------
    |
    | Path to your RSA private key for signing JWT tokens.
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
    /*
   |--------------------------------------------------------------------------
   | Authentication Defaults
   |--------------------------------------------------------------------------
   |
   | This option controls the default authentication "guard" and password
   | reset options for your application. You may change these defaults
   | as required, but they're a perfect start for most applications.
   |
   */

    'default' => [
        'guard' => 'web',
        'passwords' => 'users',
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Guards
    |--------------------------------------------------------------------------
    |
    | Next, you may define every authentication guard for your application.
    | Of course, a great default configuration has been defined for you
    | here which uses session storage and the Eloquent user provider.
    |
    | All authentication drivers have a user provider. This defines how the
    | users are actually retrieved out of your database or other storage
    | mechanisms used by this application to persist your user's data.
    |
    */

    'guards' => [
        'web' => [
            'driver' => \HyperfExtension\Auth\Guards\SessionGuard::class,
            'provider' => 'users',
            'options' => [],
        ],

        'api' => [
            'driver' => \HyperfExtension\Auth\Guards\JwtGuard::class,
            'provider' => 'users',
            'options' => [],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Providers
    |--------------------------------------------------------------------------
    |
    | All authentication drivers have a user provider. This defines how the
    | users are actually retrieved out of your database or other storage
    | mechanisms used by this application to persist your user's data.
    |
    | If you have multiple user tables or models you may configure multiple
    | sources which represent each model / table. These sources may then
    | be assigned to any extra authentication guards you have defined.
    |
    */

    'providers' => [
        'users' => [
            'driver' => \HyperfExtension\Auth\UserProviders\ModelUserProvider::class,
            'options' => [
                'model' => App\User::class,
                'hash_driver' => 'bcrypt',
            ],
        ],

        // 'users' => [
        //     'driver' => \Hyperf\Auth\UserProvider\DatabaseUserProvider::class,
        //     'options' => [
        //         'connection' => 'default',
        //         'table' => 'users',
        //         'hash_driver' => 'bcrypt',
        //     ],
        // ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Resetting Passwords
    |--------------------------------------------------------------------------
    |
    | You may specify multiple password reset configurations if you have more
    | than one user table or model in the application and you want to have
    | separate password reset settings based on the specific user types.
    |
    | The expire time is the number of minutes that the reset token should be
    | considered valid. This security feature keeps tokens short-lived so
    | they have less time to be guessed. You may change this as needed.
    |
    */

    'passwords' => [
        'users' => [
            'driver' => \HyperfExtension\Auth\Passwords\DatabaseTokenRepository::class,
            'provider' => 'users',
            'options' => [
                'connection' => null,
                'table' => 'password_resets',
                'expire' => 3600,
                'throttle' => 60,
                'hash_driver' => null,
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Confirmation Timeout
    |--------------------------------------------------------------------------
    |
    | Here you may define the amount of seconds before a password confirmation
    | times out and the user is prompted to re-enter their password via the
    | confirmation screen. By default, the timeout lasts for three hours.
    |
    */

    'password_timeout' => 10800,

    /*
    |--------------------------------------------------------------------------
    | Access Gate Policies
    |--------------------------------------------------------------------------
    |
    */

    'policies' => [
        //Model::class => Policy::class,
    ],
];
