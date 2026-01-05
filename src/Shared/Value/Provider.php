<?php
declare(strict_types=1);

namespace Konsela\Auth\Shared\Value;

use Konsela\Auth\Shared\Enum\EnumBehaviourTrait;

/**
 * @author frada <fbahezna@gmail.com>
 */
enum Provider: string
{
    use EnumBehaviourTrait;
    const APPLE = 'apple';
    const GOOGLE = 'google';
    const GOOGLE_WEB = 'google_web';
    const FACEBOOK = 'facebook';
    const REMEMBER_TOKEN = 'remember_token';
}