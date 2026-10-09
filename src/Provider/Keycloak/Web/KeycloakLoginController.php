<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak\Web;

use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The route that starts the login with Keycloak (`/auth/login`), for a link or a
 * button: without it the login only happens when a protected page sends the user
 * to Keycloak.
 *
 * A user that is already authenticated goes on to the page that follows the
 * login. The page that it comes from can be asked with `?next=/path`: only a path
 * of this site is taken, never an address of another one.
 */
class KeycloakLoginController
{
    public function __construct(
        private readonly WebConfiguration $config,
        private readonly WebFlowInterface $flow,
        private readonly KeycloakSessionManager $sessionManager
    ) {
    }

    public function login(ServerRequestInterface $request): ResponseInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        $next = $this->pathOf($request->getQueryParams()['next'] ?? null);

        $user = $request->getAttribute(MezzioUserInterface::class);
        if ($user instanceof UserInterface && !$user->isAnonymous()) {
            return new RedirectResponse($next ?? $this->config->getLoginRedirectPath());
        }

        if (!$session instanceof SessionInterface) {
            return new RedirectResponse($this->config->getLoginRedirectPath());
        }

        if ($next !== null) {
            $this->sessionManager->storeRedirectUrl($session, $next);
        }

        $this->flow->validate();

        return $this->flow->loginRedirect($request, $session)
            ?? new RedirectResponse($this->config->getLoginRedirectPath());
    }

    /**
     * A path of this site, or null: what starts with two slashes (or a slash and a
     * backslash) is not a path for a browser, it is another site.
     */
    private function pathOf(mixed $value): ?string
    {
        if (!is_string($value) || $value === '' || $value[0] !== '/') {
            return null;
        }

        return str_starts_with($value, '//') || str_starts_with($value, '/\\') ? null : $value;
    }
}
