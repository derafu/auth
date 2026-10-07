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

use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface;
use Webmozart\Assert\Assert;

/**
 * Default user factory.
 */
class UserFactory implements UserFactoryInterface
{
    /**
     * {@inheritDoc}
     *
     * The roles have to be texts and the details a map.
     */
    public function create(string $identity, array $roles = [], array $details = []): UserInterface
    {
        Assert::allString($roles);
        Assert::isMap($details);

        return new User($identity, $roles, $details);
    }

    /**
     * The factory as the callable that Mezzio asks for (the service of its
     * `UserInterface`).
     */
    public function __invoke(): callable
    {
        return $this->create(...);
    }
}
