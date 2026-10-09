<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Account;

use Derafu\Auth\Contract\AccountInterface;
use Derafu\Auth\Contract\ApiTokenManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Mezzio\Session\SessionInterface;

/**
 * The account of a provider that has a user and a password and nothing else (the
 * database and the `.htpasswd`): its profile is what every user has, a client of
 * the API sends its user and its password with `Basic`, and there are no tokens
 * (yet: the contract lets a provider add them).
 */
class BasicAccount implements AccountInterface
{
    /**
     * {@inheritDoc}
     */
    public function accountUrl(): ?string
    {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function profile(UserInterface $user, SessionInterface $session): array
    {
        return [];
    }

    /**
     * {@inheritDoc}
     */
    public function sessionDetails(SessionInterface $session): array
    {
        return [];
    }

    /**
     * {@inheritDoc}
     */
    public function apiScheme(): string
    {
        return 'Basic';
    }

    /**
     * {@inheritDoc}
     */
    public function tokens(): ?ApiTokenManagerInterface
    {
        return null;
    }
}
