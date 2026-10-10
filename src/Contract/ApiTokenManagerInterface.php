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
use Derafu\Auth\Account\NewApiToken;
use Derafu\Form\Contract\FormInterface;
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
     * The form that makes a token: what the user gives, besides being logged in (its
     * password, for example), with the help that says what to give.
     *
     * @param array<string, mixed> $data What the form has already (the body of a
     * request that is not valid).
     */
    public function form(UserInterface $user, array $data = []): FormInterface;

    /**
     * Makes a token for the user, with what it gave in the form (the body of the
     * request).
     *
     * @return NewApiToken The token, that is shown once (nothing keeps it), and what
     * the provider knows of it.
     * @throws \Derafu\Auth\Exception\AuthenticationException If the token can not be
     * made: what the user gave is not valid.
     * @throws \Derafu\Auth\Exception\FormException If the form is not valid (its
     * CSRF token, a password that is missing).
     */
    public function create(ServerRequestInterface $request, SessionInterface $session): NewApiToken;

    /**
     * Revokes a token of the user, and only that one.
     *
     * @param string $id The identifier of the token (see `ApiToken::$id`).
     * @throws \Derafu\Auth\Exception\AuthenticationException If the user has no
     * such token.
     */
    public function revoke(SessionInterface $session, string $id): void;
}
