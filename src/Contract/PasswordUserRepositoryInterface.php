<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Derafu\Auth\Exception\ConfigurationException;
use RuntimeException;

/**
 * Authenticates passwords and reloads users by identity for existing sessions.
 *
 * Database and htpasswd backends share this capability. Lookup does not require
 * a password and returns the user's current roles and details without credentials.
 */
interface PasswordUserRepositoryInterface extends UserRepositoryInterface
{
    /**
     * Authenticates an identity using its password.
     *
     * @param string $credential The user's identity in this backend.
     * @param string|null $password The supplied password; null does not authenticate.
     * @return UserInterface|null The authenticated user, or null if the identity,
     * password or account status does not allow authentication.
     * @throws ConfigurationException If the backend configuration or files cannot be used.
     * @throws RuntimeException If storage access fails.
     */
    public function authenticate(string $credential, ?string $password = null): ?UserInterface;

    /**
     * Reloads an existing user's current roles and details without a password.
     *
     * @param string $identity The user's identity in this backend.
     * @return UserInterface|null The current user, or null if it no longer exists
     * or is no longer allowed to authenticate. Passwords and hashes are excluded.
     * @throws ConfigurationException If the backend configuration or files cannot be used.
     * @throws RuntimeException If storage access fails.
     */
    public function find(string $identity): ?UserInterface;
}
