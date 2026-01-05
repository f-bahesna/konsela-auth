<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Jwt;

use InvalidArgumentException;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;

/**
 * Manages JWT encryption/decryption keys
 *
 * @author frada <fbahezna@gmail.com>
 */
final class JwtKeys
{
    /**
     * @var array<string, array<string, string>>
     */
    private array $keys = [];

    private JwtSigners $signers;

    /**
     * @param array<string, array<string, string>> $keys Configuration array with key types
     * @param JwtSigners $signers
     */
    public function __construct(array $keys, JwtSigners $signers)
    {
        $this->keys = $keys;
        $this->signers = $signers;
    }

    /**
     * Get encryption (private) key for signing
     */
    public function getEncryptKey(string $algo): Key
    {
        $keyType = $this->getKeyType($algo);
        $this->assertKeyExists($keyType);

        if ($this->signers->get($algo) instanceof Rsa) {
            $privateKey = $this->keys[$keyType]['private_key'] ?? null;
            if (!$privateKey) {
                throw new InvalidArgumentException(
                    sprintf('Private key not configured for algorithm "%s"', $algo)
                );
            }

            $passphrase = $this->keys[$keyType]['passphrase'] ?? '';

            // Use InMemory::file() for lcobucci/jwt v5.x
            return empty($passphrase)
                ? InMemory::file($privateKey)
                : InMemory::file($privateKey, $passphrase);
        }

        $secretKey = $this->keys[$keyType]['secret_key'] ?? null;
        if (!$secretKey) {
            throw new InvalidArgumentException(
                sprintf('Secret key not configured for algorithm "%s"', $algo)
            );
        }

        return InMemory::plainText($secretKey);
    }

    /**
     * Get decryption (public) key for verification
     */
    public function getDecryptKey(string $algo): Key
    {
        $keyType = $this->getKeyType($algo);
        $this->assertKeyExists($keyType);

        if ($this->signers->get($algo) instanceof Rsa) {
            $publicKey = $this->keys[$keyType]['public_key'] ?? null;
            if (!$publicKey) {
                throw new InvalidArgumentException(
                    sprintf('Public key not configured for algorithm "%s"', $algo)
                );
            }

            // Use InMemory::file() for lcobucci/jwt v5.x
            return InMemory::file($publicKey);
        }

        $secretKey = $this->keys[$keyType]['secret_key'] ?? null;
        if (!$secretKey) {
            throw new InvalidArgumentException(
                sprintf('Secret key not configured for algorithm "%s"', $algo)
            );
        }

        return InMemory::plainText($secretKey);
    }

    /**
     * Extract key type from algorithm (e.g., RS256 -> rs, HS256 -> hs)
     */
    private function getKeyType(string $algo): string
    {
        return strtolower(substr($algo, 0, 2));
    }

    private function assertKeyExists(string $keyType): void
    {
        if (!isset($this->keys[$keyType])) {
            throw new InvalidArgumentException(
                sprintf('JWT keys not configured for type "%s"', $keyType)
            );
        }
    }
}
