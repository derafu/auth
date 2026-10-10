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

use Psr\Http\Message\ServerRequestInterface;

/**
 * What a provider gives to the API channel: the scheme of the header
 * `Authorization` that it reads (`Bearer` for a token, `Basic` for a user and a
 * password) and how it verifies what a client sends with it.
 */
interface ApiSchemeInterface
{
    /**
     * The scheme of the header `Authorization`: `Bearer`, `Basic`.
     */
    public function scheme(): string;

    /**
     * Checks that what the scheme needs to work is configured.
     *
     * @throws \Derafu\Auth\Exception\ConfigurationException If something is not.
     */
    public function validate(): void;

    /**
     * Authenticates a client by the credentials that it sent. It is done in each
     * request, and nothing is kept.
     *
     * @param string $credentials What comes after the scheme: the token, or the
     * user and the password in Base64.
     * @return UserInterface|null The user, or null if the credentials are not valid.
     * @throws \Derafu\Auth\Exception\AuthenticationException If the credentials are
     * not valid and the scheme can say why: the message of the exception, in English
     * and without what a header can not have, is the reason that the 401 gives to the
     * client.
     */
    public function authenticate(ServerRequestInterface $request, string $credentials): ?UserInterface;

    /**
     * What the response 401 says in the header `WWW-Authenticate`: how to
     * authenticate (RFC 7235).
     *
     * @param string $realm The label of the protection space.
     * @param bool $credentialsSent Whether the request sent credentials of this
     * scheme (that were not valid).
     * @param string|null $reason Why they were not valid, if the scheme said it.
     * @return string|null The challenge, or null if it is not to be sent.
     */
    public function challenge(ServerRequestInterface $request, string $realm, bool $credentialsSent, ?string $reason = null): ?string;
}
