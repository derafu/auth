<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface;

/**
 * The factory that an application registers to have its own class of user in
 * both providers.
 */
final class CustomUserFactory implements UserFactoryInterface
{
    public function create(string $identity, array $roles = [], array $details = []): UserInterface
    {
        return new CustomUser($identity, $roles, $details);
    }
}
