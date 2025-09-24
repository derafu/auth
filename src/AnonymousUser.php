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

/**
 * Anonymous user implementation.
 *
 * This class represents an anonymous user and implements our UserInterface
 * to provide user information to the application.
 */
class AnonymousUser extends User implements UserInterface
{
    /**
     * Creates a new anonymous user.
     */
    public function __construct()
    {
        parent::__construct('anonymous', ['anonymous']);
    }

    /**
     * {@inheritDoc}
     */
    public function isAnonymous(): bool
    {
        return true;
    }
}
