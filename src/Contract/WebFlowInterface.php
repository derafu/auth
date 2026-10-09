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

use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What a provider gives to the web channel: its way to log a user in, to read it
 * back from the session and to log it out.
 *
 * The web channel does what is the same for every provider (the session, the page
 * that is remembered, the flash messages, the redirects) and asks the flow for
 * what is its own: Keycloak sends the user to Keycloak and takes it back from its
 * callback, a database asks for a user and a password in a form.
 */
interface WebFlowInterface
{
    /**
     * The path of the login: the page with the form, or the callback of the
     * provider. It is public: the way in is not protected.
     */
    public function loginPath(): string;

    /**
     * Checks that what the flow needs to work is configured.
     *
     * @throws \Derafu\Auth\Exception\ConfigurationException If something is not.
     */
    public function validate(): void;

    /**
     * Handles the request to the login path: the callback of the provider, or
     * the form that was sent.
     *
     * @return UserInterface|null The user that logged in, or null if it did not.
     */
    public function login(ServerRequestInterface $request, SessionInterface $session): ?UserInterface;

    /**
     * Gets the user that the session has, asking the provider again when it is
     * due (its roles, whether it still exists).
     *
     * @return UserInterface|null The user, or null if it can not be told.
     */
    public function userFromSession(SessionInterface $session): ?UserInterface;

    /**
     * Gets where the user is sent after the logout when it is not the page of the
     * site: the address with which the provider ends its own session. It is asked
     * before the session of the site is closed, that is what it may need.
     *
     * @return string|null The address, or null to go to the page that follows the
     * logout.
     */
    public function logoutUrl(ServerRequestInterface $request, ?SessionInterface $session): ?string;

    /**
     * Gets the response that sends an unauthenticated user to the login of the
     * provider (Keycloak), if the login is not a page of the site.
     *
     * @return ResponseInterface|null The response, or null to send the user to the
     * login page of the site.
     */
    public function loginRedirect(ServerRequestInterface $request, SessionInterface $session): ?ResponseInterface;
}
