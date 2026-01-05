<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Authentication\Authenticator;

use Konsela\Auth\Domain\Contract\AuthenticatableInterface;
use Konsela\Auth\Domain\Exception\AuthenticationException;
use Konsela\Auth\Infrastructure\Authentication\Model\AuthenticatedUser;
use Konsela\Auth\Infrastructure\Jwt\JwtService;
use Konsela\Auth\Shared\Value\Signature;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;

/**
 * JWT-based authenticator
 *
 * @author frada <fbahezna@gmail.com>
 */
final class JwtAuthenticator implements AuthenticatorInterface
{
    private const NAME = 'jwt';

    private JwtService $jwt;
    private string $defaultAlgo;
    private ?int $ttl;
    private ?string $issuer;
    private ?string $audience;

    public function __construct(
        JwtService $jwt,
        string $defaultAlgo = 'RS256',
        ?int $ttl = null,
        ?string $issuer = null,
        ?string $audience = null
    ) {
        $this->jwt = $jwt;
        $this->defaultAlgo = $defaultAlgo;
        $this->ttl = $ttl;
        $this->issuer = $issuer;
        $this->audience = $audience;
    }

    public function sign(AuthenticatableInterface $user, array $payload = []): Signature
    {
        $claims = array_merge($user->getSignPayload(), $payload);

        // Add standard JWT claims
        if ($this->ttl !== null) {
            $claims['exp'] = date('Y-m-d H:i:s', strtotime(sprintf('+%d seconds', $this->ttl)));
        }

        if ($this->issuer !== null) {
            $claims['iss'] = $this->issuer;
        }

        if ($this->audience !== null) {
            $claims['aud'] = $this->audience;
        }

        $token = $this->jwt->sign($this->defaultAlgo, $claims);

        return new Signature(
            $token->toString(),
            'Bearer',
            ['expires_in' => $this->ttl]
        );
    }

    public function verify(Signature $signature): ?AuthenticatedUser
    {
        try {
            $parser = new Parser(new JoseEncoder());
            /** @var Plain $token */
            $token = $parser->parse($signature->getToken());

            // Verify token signature and expiration
            if ($this->jwt->verify($token)) {
                $claims = $token->claims()->all();

                return new AuthenticatedUser(
                    (string) $token->claims()->get('sub'),
                    $claims
                );
            }
        } catch (AuthenticationException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw AuthenticationException::invalidToken($e->getMessage());
        }

        return null;
    }

    public function getName(): string
    {
        return self::NAME;
    }
}
