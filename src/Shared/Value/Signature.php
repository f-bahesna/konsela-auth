<?php
declare(strict_types=1);

namespace Konsela\Auth\Shared\Value;

use Illuminate\Contracts\Support\Arrayable;

/**
 * @author frada <fbahezna@gmail.com>
 */
final class Signature implements Arrayable
{
    /**
     * @var string
     */
    private $token;

    /**
     * @var string
     */
    private $type;

    /**
     * @var array
     */
    private $attributes;

    /**
     * Constructor.
     *
     * @param string $token
     * @param string $type
     * @param array  $attributes
     */
    public function __construct(string $token, string $type, array $attributes = [])
    {
        $this->token = $token;
        $this->type = $type;
        $this->attributes = $attributes;
    }

    /**
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * {@inheritdoc}
     */
    public function toArray(): array
    {
        return array_merge(
            $this->attributes,
            [
                'token' => $this->token,
                'type'  => $this->type,
            ]
        );
    }
}
