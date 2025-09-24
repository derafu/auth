<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth;

use Derafu\Auth\Contract\UserInterface;
use Webmozart\Assert\Assert;

/**
 * Default user factory.
 */
class UserFactory
{
    public function __invoke(): callable
    {
        return static function (string $identity, array $roles = [], array $details = []): UserInterface {
            Assert::allString($roles);
            Assert::isMap($details);

            return new User($identity, $roles, $details);
        };
    }
}
