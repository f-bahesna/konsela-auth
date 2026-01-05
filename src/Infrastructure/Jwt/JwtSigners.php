<?php
declare(strict_types=1);

namespace Konsela\Auth\Infrastructure\Jwt;

use Lcobucci\JWT\Signer;
use RuntimeException;

/**
 * Manages JWT signing algorithms
 *
 * @author frada <fbahezna@gmail.com>
 */
final class JwtSigners
{
    /**
     * @var array<string, Signer>
     */
    private array $signers = [];

    /**
     * @param array<string, Signer> $signers
     */
    public function __construct(array $signers)
    {
        foreach ($signers as $signer) {
            $this->add($signer);
        }
    }

    public function add(Signer $signer): void
    {
        $this->signers[$signer->algorithmId()] = $signer;
    }

    public function get(string $algo): Signer
    {
        if (!array_key_exists($algo, $this->signers)) {
            throw new RuntimeException(
                sprintf('JWT signer with algorithm "%s" not found.', $algo)
            );
        }

        return $this->signers[$algo];
    }

    public function has(string $algo): bool
    {
        return array_key_exists($algo, $this->signers);
    }
}
