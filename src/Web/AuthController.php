<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Web;

use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Renderer\Contract\RendererInterface;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The routes of the login and the logout, the same for every provider: what is of
 * the provider is in its `WebFlowInterface`.
 *
 * The login and the logout are done by the web channel (`WebChannel`, with the
 * flow of the provider), before a request gets here, whether the paths are
 * protected or not: the authentication processes the form or exchanges the code
 * of the provider, renews the session, and closes it. What is left for the
 * controller is what the user sees: the form, or the redirect.
 */
class AuthController
{
    /**
     * @param RendererInterface $renderer The renderer of the login page.
     * @param FormManagerInterface $formManager The forms of the provider.
     * @param WebConfiguration $config The configuration of the web channel.
     * @param SessionManagerInterface $sessionManager The session manager.
     * @param WebFlowInterface $flow The flow of the provider.
     */
    public function __construct(
        private readonly RendererInterface $renderer,
        private readonly FormManagerInterface $formManager,
        private readonly WebConfiguration $config,
        private readonly SessionManagerInterface $sessionManager,
        private readonly WebFlowInterface $flow
    ) {
    }

    /**
     * The login: the form of the site, or the way to the page of the provider.
     *
     * A user that is logged in (it just logged in, or it is on the login page
     * while it is) goes where it was going, or to the page that follows the
     * login: the login is a POST, and after it comes a redirect, so a reload does
     * not send the form again.
     *
     * @param ServerRequestInterface $request The request. A query `next` with a
     * path of the site says where to go after the login.
     * @return string|ResponseInterface The rendered login page, or a redirect.
     */
    public function login(ServerRequestInterface $request): string|ResponseInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        $session = $session instanceof SessionInterface ? $session : null;
        $user = $request->getAttribute(MezzioUserInterface::class);

        $next = $this->pathOf($request->getQueryParams()['next'] ?? null);
        if ($next !== null && $session !== null) {
            $this->sessionManager->storeRedirectUrl($session, $next);
        }

        if ($user instanceof UserInterface && !$user->isAnonymous()) {
            $redirectUrl = $next
                ?? ($session !== null ? $this->sessionManager->getRedirectUrl($session) : null)
                ?: $this->config->getLoginRedirectPath()
            ;
            if ($session !== null) {
                $this->sessionManager->clearRedirectUrl($session);
            }

            return new RedirectResponse($redirectUrl);
        }

        // The login is at the provider: there is no form to show.
        $form = $this->flow->loginForm();
        if ($form === null) {
            if ($session === null) {
                return new RedirectResponse($this->config->getLoginRedirectPath());
            }
            $this->flow->validate();

            return $this->flow->loginRedirect($request, $session)
                ?? new RedirectResponse($this->config->getLoginRedirectPath());
        }

        // A request without a body (it is null in some PSR-7 implementations) is a
        // form without data.
        $body = $request->getParsedBody();

        return $this->renderer->render('auth/login', [
            'form' => $this->formManager->createForm($form, is_array($body) ? $body : []),
        ]);
    }

    /**
     * The callback of a provider that takes the user to its own page, after the
     * login was done: the user goes to the page that was requested before the
     * login, or to the page that follows it.
     *
     * @throws AuthenticationException With 404 if the provider has no callback (the
     * login is a form of the site), and with 400 if the request is not the one of
     * a user that logged in.
     */
    public function callback(ServerRequestInterface $request): ResponseInterface
    {
        if ($this->flow->loginForm() !== null) {
            throw new AuthenticationException('This provider has no callback.', 404);
        }

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
            ?: $this->config->getLoginRedirectPath()
        ;
        $this->sessionManager->clearRedirectUrl($session);

        return new RedirectResponse($redirectUrl);
    }

    /**
     * The logout that the authentication did not handle (it is handled before,
     * when the session is closed): it only redirects.
     */
    public function logout(ServerRequestInterface $request): ResponseInterface
    {
        return new RedirectResponse($this->config->getLogoutRedirectPath());
    }

    /**
     * A path of the site, or null: what is not one (another site, a protocol, an
     * empty text) is not a place to send the user to.
     */
    private function pathOf(mixed $value): ?string
    {
        if (!is_string($value) || $value === '' || $value[0] !== '/') {
            return null;
        }

        return str_starts_with($value, '//') || str_starts_with($value, '/\\') ? null : $value;
    }
}
