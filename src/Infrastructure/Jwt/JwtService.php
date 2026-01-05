<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Jwt;

use DateTimeImmutable;
use Konsela\Auth\Domain\Exception\AuthenticationException;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Plain;

/**
 * Core JWT service for signing and verifying tokens
 *
 * @author frada <fbahezna@gmail.com>
 */
final class JwtService
{
    private JwtSigners $signers;
    private JwtKeys $keys;

    public function __construct(JwtSigners $signers, JwtKeys $keys)
    {
        $this->signers = $signers;
        $this->keys = $keys;
    }

    /**
     * Sign a JWT token with the given algorithm and claims
     *
     * @param string $algo Algorithm to use (e.g., RS256, HS256)
     * @param array<string, mixed> $claims JWT claims
     * @return Plain
     */
    public function sign(string $algo, array $claims): Plain
    {
        $tokenBuilder = new Builder(
            new JoseEncoder(),
            ChainedFormatter::withUnixTimestampDates()
        );

        // Process each claim according to JWT standards (RFC 7519)
        foreach ($claims as $key => $value) {
            switch ($key) {
                case 'id':
                case 'jti':
                    $tokenBuilder = $tokenBuilder->identifiedBy((string) $value);
                    break;

                case 'sub':
                    $tokenBuilder = $tokenBuilder->relatedTo((string) $value);
                    break;

                case 'exp':
                    $tokenBuilder = $tokenBuilder->expiresAt(new DateTimeImmutable($value));
                    break;

                case 'iss':
                    $tokenBuilder = $tokenBuilder->issuedBy((string) $value);
                    break;

                case 'iat':
                    $timestamp = is_numeric($value)
                        ? (new DateTimeImmutable())->setTimestamp((int) $value)
                        : new DateTimeImmutable($value);
                    $tokenBuilder = $tokenBuilder->issuedAt($timestamp);
                    break;

                case 'nbf':
                    $tokenBuilder = $tokenBuilder->canOnlyBeUsedAfter(new DateTimeImmutable($value));
                    break;

                case 'aud':
                    // Handle audience - can be string or array
                    $audiences = is_array($value) ? $value : [$value];
                    foreach ($audiences as $audience) {
                        $tokenBuilder = $tokenBuilder->permittedFor((string) $audience);
                    }
                    break;

                default:
                    // Custom claims
                    $tokenBuilder = $tokenBuilder->withClaim($key, $value);
                    break;
            }
        }

        $signer = $this->signers->get($algo);
        $key = $this->keys->getEncryptKey($algo);

        return $tokenBuilder->getToken($signer, $key);
    }

    /**
     * Verify a JWT token
     *
     * @param Plain $token
     * @return bool
     * @throws AuthenticationException
     */
    public function verify(Plain $token): bool
    {
        $algo = $token->headers()->get('alg');

        if (!$algo) {
            throw AuthenticationException::invalidToken('Missing algorithm in token header');
        }

        $signer = $this->signers->get($algo);
        $key = $this->keys->getDecryptKey($algo);

        $verified = $signer->verify(
            $token->signature()->hash(),
            $token->payload(),
            $key
        );

        if (!$verified) {
            throw AuthenticationException::invalidToken('Token signature verification failed');
        }

        // Check token expiration
        if ($token->isExpired(new DateTimeImmutable())) {
            throw AuthenticationException::tokenExpired();
        }

        return true;
    }
}
