<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication\Channel\Web;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Identification;
use Derafu\Auth\Contract\ChannelInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The web channel: a user logs in once and the session remembers it.
 *
 * It does what is the same for every provider: reads the session, remembers the
 * page that was requested, tells the user with flash messages, and redirects (to
 * the login, after the logout). What is of the provider (how the user logs in,
 * how the session is read back, where the login is) it asks the web flow.
 *
 * It is the channel of every request that is not of another one, so it must be
 * the last one that the manager asks.
 */
final class WebChannel implements ChannelInterface
{
    /**
     * Creates the web channel.
     *
     * @param WebFlowInterface $flow What the provider gives to the channel.
     * @param WebConfiguration $config The paths and the refresh of the session.
     * @param SessionManagerInterface $sessionManager The session manager.
     * @param UserInterface $anonymousUser The anonymous user.
     */
    public function __construct(
        private readonly WebFlowInterface $flow,
        private readonly WebConfiguration $config,
        private readonly SessionManagerInterface $sessionManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser()
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function name(): string
    {
        return 'web';
    }

    /**
     * {@inheritDoc}
     *
     * Every request: it is the channel that is left when no other one is asked.
     */
    public function matches(ServerRequestInterface $request): bool
    {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * The logout and the login are done before the access rules are asked: they
     * are the way out and the way in, so a protected path that includes them must
     * not turn them away.
     */
    public function identify(ServerRequestInterface $request): Identification
    {
        $path = $request->getUri()->getPath();
        $session = $this->sessionOf($request);

        // Handle logout: the request ends here, it is answered by
        // `unauthorizedResponse()`, that closes the session. Only a logout request
        // does it: anything else to that path is not a logout, and it goes on to
        // the controller of the route, that sends the user away.
        if ($this->isLogoutPath($path)) {
            return $this->isLogoutRequest($request)
                ? Identification::halt()
                : Identification::of($this->userFromSession($session))
            ;
        }

        // Handle login. The login path is public: the user is the one that the
        // login gives, or the one that the session already had.
        $user = $this->userFromSession($session);
        if ($this->isLoginPath($path) && $session) {
            $this->flow->validate();
            $user = $this->flow->login($request, $session) ?? $user;
        }

        return Identification::of($user);
    }

    /**
     * {@inheritDoc}
     */
    public function isPublic(ServerRequestInterface $request): bool
    {
        $path = $request->getUri()->getPath();

        return $this->isLoginPath($path) || $this->isLogoutPath($path);
    }

    /**
     * {@inheritDoc}
     */
    public function unauthorizedResponse(ServerRequestInterface $request): ResponseInterface
    {
        $session = $this->sessionOf($request);

        if ($this->isLogoutPath($request->getUri()->getPath())) {
            return $this->logout($request, $session);
        }

        // The user is sent to the login of the provider if it is not a page of
        // the site (Keycloak), or to the login page of the site. The page that it
        // asked for is remembered, to take it back after the login.
        $this->flow->validate();

        if ($session) {
            $this->rememberPage($request, $session);

            $response = $this->flow->loginRedirect($request, $session);
            if ($response !== null) {
                return $response;
            }
        }

        Flash::error(
            $request,
            'You must be logged in to access the requested page {path}',
            ['path' => $request->getUri()->getPath()]
        );

        return new RedirectResponse($this->config->getUnauthorizedRedirectPath());
    }

    /**
     * Closes the session and sends the user away: to the address of the provider
     * if it ends its own session there too, or to the page that follows the
     * logout.
     */
    private function logout(ServerRequestInterface $request, ?SessionInterface $session): ResponseInterface
    {
        // Asked before the session is closed: it is what the provider may need.
        $url = $this->flow->logoutUrl($request, $session);

        if ($session) {
            $this->sessionManager->clearSession($session);

            // The identifier that the session had must be of no use after logout.
            $this->sessionManager->regenerate($session);
        }

        Flash::success($request, 'The session has been closed successfully.');

        return new RedirectResponse($url ?? $this->config->getLogoutRedirectPath());
    }

    /**
     * Gets the user that the session has, or the anonymous one.
     */
    private function userFromSession(?SessionInterface $session): UserInterface
    {
        // If there is no session, return the anonymous user.
        if (!$session) {
            return $this->anonymousUser;
        }

        // The user must be already authenticated.
        if (!$this->sessionManager->hasAuthInfo($session)) {
            return $this->anonymousUser;
        }

        // A provider that is not configured can not tell who the session is, so
        // what the session says is not believed (the user may have logged in when
        // it was configured): the visitor is the anonymous one. The pages that
        // nobody protects keep working, and where the provider is needed (a
        // protected page, the login) it says which variable is missing.
        try {
            $this->flow->validate();
        } catch (ConfigurationException) {
            return $this->anonymousUser;
        }

        // The authenticated user of the session, or the anonymous one if the
        // provider can not tell.
        return $this->flow->userFromSession($session) ?? $this->anonymousUser;
    }

    /**
     * Gets the session from the request.
     */
    private function sessionOf(ServerRequestInterface $request): ?SessionInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);

        return $session instanceof SessionInterface ? $session : null;
    }

    /**
     * Checks if a path is the login route: the one of the provider.
     */
    private function isLoginPath(string $path): bool
    {
        return $path === $this->flow->loginPath();
    }

    /**
     * Checks if a path is the logout route.
     */
    private function isLogoutPath(string $path): bool
    {
        return $path === $this->config->getLogoutPath();
    }

    /**
     * Checks if a request to the logout path is a logout.
     *
     * A logout is a POST that comes from the same origin: a logout that a link
     * or an image of another site could trigger (a GET, or a POST from another
     * site) is a cross-site request forgery. The origin is what the browser says
     * in `Sec-Fetch-Site` or in `Origin`; a request that has neither is not made
     * by a browser, and a browser always sends one of them in a POST.
     */
    private function isLogoutRequest(ServerRequestInterface $request): bool
    {
        return strtoupper($request->getMethod()) === 'POST' && $this->isSameOrigin($request);
    }

    /**
     * Checks if a request comes from the same origin, by what the browser says.
     *
     * @return bool True if it does, or if it does not say (it is not a browser).
     */
    private function isSameOrigin(ServerRequestInterface $request): bool
    {
        $site = $request->getHeaderLine('Sec-Fetch-Site');
        if ($site !== '') {
            return in_array($site, ['same-origin', 'none'], true);
        }

        $origin = $request->getHeaderLine('Origin');
        if ($origin === '') {
            return true;
        }

        $port = static fn (?string $scheme, ?int $port): ?int => $port
            ?? ['http' => 80, 'https' => 443][strtolower((string) $scheme)] ?? null;

        $from = parse_url($origin);
        $uri = $request->getUri();

        return strtolower((string) ($from['scheme'] ?? '')) === strtolower($uri->getScheme())
            && strtolower((string) ($from['host'] ?? '')) === strtolower($uri->getHost())
            && $port($from['scheme'] ?? null, $from['port'] ?? null) === $port($uri->getScheme(), $uri->getPort());
    }

    /**
     * Remembers the current page, for the redirect after the authentication.
     *
     * Only its path and query are stored, so what is stored never takes the user
     * to another site (the host of a request is not to be trusted).
     */
    private function rememberPage(ServerRequestInterface $request, SessionInterface $session): void
    {
        $uri = $request->getUri();

        // A path that starts with two slashes (or a slash and a backslash) is
        // not a path for a browser, it is another site: it is made one.
        $path = '/' . ltrim($uri->getPath(), '/\\');

        $this->sessionManager->storeRedirectUrl(
            $session,
            $path . ($uri->getQuery() !== '' ? '?' . $uri->getQuery() : '')
        );
    }
}
