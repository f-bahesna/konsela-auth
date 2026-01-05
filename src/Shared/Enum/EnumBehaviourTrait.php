<?php
declare(strict_types=1);

namespace Konsela\Auth\Shared\Enum;

/**
 * @author frada <fbahezna@gmail.com>
 */
trait EnumBehaviourTrait
{
    public function is($enumerator): bool
    {
        return $this === $enumerator || $this->value === $enumerator;
    }

    public function getValue(): string|int
    {
        return $this->value;
    }

    public function getValues(): array
    {
        return
            collect(self::cases())
            ->map(fn (self $case) => $case->value)
            ->toArray();
    }
}