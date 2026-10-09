<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Derafu\Auth\Account\ApiToken;
use Derafu\Translation\Contract\TranslatableMessageInterface;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The tokens of the API that a user has: a user can have as many as it wants,
 * and it can revoke them one by one.
 *
 * A token is not kept by the application: it is shown once, when it is made, and
 * what the user sees after that is its data (when it was made, when it was last
 * used...), which is what the provider says about it. Each token is its own session
 * in the provider: revoking one does not touch the others.
 */
interface ApiTokenManagerInterface
{
    /**
     * The tokens of the user.
     *
     * @return list<ApiToken> The tokens, the newest first.
     */
    public function list(SessionInterface $session): array;

    /**
     * What the user gives to make a token, besides being logged in: the fields of the
     * form (its password, for example).
     *
     * @return list<array{name: string, label: TranslatableMessageInterface|string, type: string, required: bool}>
     */
    public function fields(): array;

    /**
     * Makes a token for the user, with what it gave in the form (the body of the
     * request).
     *
     * @return string The token. It is shown once: nothing keeps it.
     * @throws \Derafu\Auth\Exception\AuthenticationException If the token can not be
     * made: what the user gave is not valid.
     */
    public function create(ServerRequestInterface $request, SessionInterface $session): string;

    /**
     * Revokes a token of the user, and only that one.
     *
     * @param string $id The identifier of the token (see `ApiToken::$id`).
     * @throws \Derafu\Auth\Exception\AuthenticationException If the user has no
     * such token.
     */
    public function revoke(SessionInterface $session, string $id): void;
}
