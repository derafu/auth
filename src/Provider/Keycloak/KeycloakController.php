<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak;

use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Controller of the routes of Keycloak: the callback and the logout.
 *
 * The login and the logout are done by `KeycloakAuthentication`, before a
 * request gets here, whether the paths are protected or not: the authentication
 * exchanges the code and renews the session, and closes the session. What is
 * left for the controller is the redirect.
 */
class KeycloakController implements RequestHandlerInterface
{
    /**
     * Constructor of the Keycloak controller.
     *
     * @param KeycloakConfiguration $config The configuration.
     * @param KeycloakSessionManager $sessionManager The session manager.
     */
    public function __construct(
        private readonly KeycloakConfiguration $config,
        private readonly KeycloakSessionManager $sessionManager,
    ) {
    }

    /**
     * Handles the callback of Keycloak, after the login was done: the user goes
     * to the page that was requested before the login, or to the page that
     * follows the login.
     *
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     * @throws AuthenticationException If the request is not the one of a user
     * that logged in.
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $user = $request->getAttribute(MezzioUserInterface::class);
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);

        if (
            !$user instanceof UserInterface
            || $user->isAnonymous()
            || !$session instanceof SessionInterface
        ) {
            throw new AuthenticationException('The login was not completed.', 400);
        }

        $redirectUrl = $this->sessionManager->getRedirectUrl($session)
            ?: $this->config->getLoginRedirectRoute()
        ;
        $this->sessionManager->clearRedirectUrl($session);

        return new RedirectResponse($redirectUrl);
    }

    /**
     * Handles the logout request that the authentication did not handle (it
     * does it before this, when it is on the pipeline): the user goes to the
     * page that follows the logout.
     *
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function logout(ServerRequestInterface $request): ResponseInterface
    {
        return new RedirectResponse($this->config->getLogoutRedirectRoute());
    }
}
