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

/**
 * Makes the users that the providers give.
 *
 * Both providers work out the same three things from what their source says (the
 * database from its queries, Keycloak from its claims) and give them here: the
 * identity, the roles and the details. An application that has its own class of
 * user (with getters for its own fields) registers its factory in the container
 * in place of the default one, and the users of both providers are of that class.
 */
interface UserFactoryInterface
{
    /**
     * Makes a user.
     *
     * @param string $identity The identity of the user.
     * @param list<string> $roles The roles of the user.
     * @param array<string, mixed> $details The details of the user: what the
     * provider knows about it (the standard fields, when it has them, and any
     * other).
     * @return UserInterface The user.
     */
    public function create(string $identity, array $roles = [], array $details = []): UserInterface;
}
