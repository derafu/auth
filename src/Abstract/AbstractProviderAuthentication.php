<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Abstract;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authorization;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Support\Url;
use Derafu\Translation\Contract\TranslatableMessageInterface;
use Derafu\Translation\TranslatableMessage;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Abstract provider authentication.
 */
abstract class AbstractProviderAuthentication implements AuthenticationInterface
{
    /**
     * Creates a new abstract provider authentication.
     *
     * @param ConfigurationInterface $config The configuration.
     * @param SessionManagerInterface $sessionManager The session manager.
     * @param UserInterface $anonymousUser The anonymous user.
     * @param TranslatorInterface|null $translator Translates the title and the
     * detail of the response of an unauthenticated request to the API, in the
     * language of the translator. Without it they are in English.
     */
    public function __construct(
        private readonly ConfigurationInterface $config,
        private readonly SessionManagerInterface $sessionManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser(),
        private readonly ?TranslatorInterface $translator = null
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request): ?UserInterface
    {
        // Get the path, session and user from the request.
        $path = $request->getUri()->getPath();
        $session = $this->getSessionFromRequest($request);
        $user = $this->getUserFromSession($session);

        // The logout and the login are done before looking at what is
        // protected: they are the way out and the way in, so a protected path
        // that includes them must not turn them away.

        // Handle logout. It is null to trigger the unauthorized response, that
        // closes the session (see handleLogout()). Only a logout request does
        // it: anything else to that path is not a logout, and it goes on to the
        // controller of the route, that sends the user away.
        if ($this->isLogoutPath($path)) {
            return $this->isLogoutRequest($request) ? null : $user;
        }

        // Handle login. The login path is public: the user is the one that the
        // login gives, or the one that the session already had.
        if ($this->isLoginPath($path)) {
            if ($session) {
                $user = $this->handleLogin($request, $session) ?? $user;
            }

            return $user;
        }

        // If the path is not protected and its route does not declare roles,
        // return the user (authenticated or anonymous). A route that declares
        // roles is protected, even when the site did not list its path.
        if (
            !$this->config->requiresAuth($path)
            && empty(Authorization::routeRoles($request))
        ) {
            return $user;
        }

        // If the path is protected, the user must be authenticated. Null
        // triggers the unauthorized response.
        if ($user->isAnonymous()) {
            return null;
        }

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function unauthorizedResponse(
        ServerRequestInterface $request
    ): PsrResponseInterface {
        // Get the path and session from the request.
        $path = $request->getUri()->getPath();
        $session = $this->getSessionFromRequest($request);

        // Handle logout.
        if ($this->isLogoutPath($path)) {
            return $this->handleLogout($request);
        }

        // Handle an unauthorized request to the API: a client of the API gets
        // the answer, with a session or without it (the session middleware gives
        // one to every request), not a redirect to a login that it can not use.
        if (Url::pathStartsWith($path, '/api')) {
            return $this->handleUnauthorizedApi();
        }

        // Handle unauthorized request (with session).
        if ($session) {
            return $this->handleUnauthorized($request, $session);
        }

        // Handle unauthenticated request (without session).
        return $this->handleUnauthenticated($request);
    }

    /**
     * Gets flash messages from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return mixed The flash messages or null if not available.
     */
    protected function getFlashFromRequest(ServerRequestInterface $request): mixed
    {
        return $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE);
    }

    /**
     * Adds an error flash message.
     *
     * The flash message is the message as data (its id, its parameters and its
     * domain), not a text: it is translated when it is shown, in the language of
     * whoever sees it (see `partials/flash-messages.html.twig`). A session that
     * keeps JSON, like the one of Mezzio, can keep it.
     *
     * @param ServerRequestInterface $request The request.
     * @param string|TranslatableMessageInterface $message The message: its text
     * in English, which is its translation id, or a message already made (the
     * one of an exception, for example).
     * @param array<string, mixed> $parameters The parameters of the text. A
     * message that is already made has its own.
     * @param bool $now Whether to add the flash message immediately.
     */
    protected function addErrorFlash(
        ServerRequestInterface $request,
        string|TranslatableMessageInterface $message,
        array $parameters = [],
        bool $now = false
    ): void {
        $flash = $this->getFlashFromRequest($request);
        if ($flash) {
            $message = $message instanceof TranslatableMessageInterface
                ? $message
                : new TranslatableMessage($message, $parameters, 'auth');

            if ($now) {
                if (method_exists($flash, 'flashNow')) {
                    $flash->flashNow('error', $message, 0);
                }
            } else {
                if (method_exists($flash, 'flash')) {
                    $flash->flash('error', $message);
                }
            }
        }
    }

    /**
     * Adds a success flash message.
     *
     * It is a message as data, like the one of `addErrorFlash()`.
     *
     * @param ServerRequestInterface $request The request.
     * @param string|TranslatableMessageInterface $message The message: its text
     * in English, which is its translation id, or a message already made.
     * @param array<string, mixed> $parameters The parameters of the text. A
     * message that is already made has its own.
     * @param bool $now Whether to add the flash message immediately.
     */
    protected function addSuccessFlash(
        ServerRequestInterface $request,
        string|TranslatableMessageInterface $message,
        array $parameters = [],
        bool $now = false
    ): void {
        $flash = $this->getFlashFromRequest($request);
        if ($flash) {
            $message = $message instanceof TranslatableMessageInterface
                ? $message
                : new TranslatableMessage($message, $parameters, 'auth');

            if ($now) {
                if (method_exists($flash, 'addFlashNow')) {
                    $flash->addFlashNow('success', $message, 0);
                }
            } else {
                if (method_exists($flash, 'flash')) {
                    $flash->flash('success', $message);
                }
            }
        }
    }

    /**
     * Gets who the client of the request is, to count its failed logins.
     *
     * It is the network of the client that the HTTP layer decided, if it did: the
     * attribute `client_network` of the request (`ClientIpMiddleware` of
     * `derafu/http` leaves it, deciding which proxies are trusted to say who the
     * client is). Without it, it is the address of the connection. The headers of
     * the request (`X-Forwarded-For`...) are never read here: they are written by
     * the client, so it could choose its own counter and try as many passwords as
     * it wants.
     *
     * @param ServerRequestInterface $request The request.
     * @return string The network of the client, or its address.
     */
    protected function clientAddress(ServerRequestInterface $request): string
    {
        $network = $request->getAttribute('client_network');
        if (is_string($network) && $network !== '') {
            return $network;
        }

        return (string) ($request->getServerParams()['REMOTE_ADDR'] ?? 'unknown');
    }

    /**
     * Gets the session from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return SessionInterface|null The session or null if not found.
     */
    protected function getSessionFromRequest(ServerRequestInterface $request): ?SessionInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);

        if (!$session instanceof SessionInterface) {
            return null;
        }

        return $session;
    }

    /**
     * Gets the user from the session.
     *
     * @param SessionInterface|null $session The session.
     * @return UserInterface The user.
     */
    protected function getUserFromSession(?SessionInterface $session): UserInterface
    {
        // If there is no session, return the anonymous user.
        if (!$session) {
            return $this->anonymousUser;
        }

        // Check if user is already authenticated.
        if (!$this->sessionManager->hasAuthInfo($session)) {
            return $this->anonymousUser;
        }

        // Get the authenticated user from the session.
        $user = $this->getAuthenticatedUserFromSession($session);
        if ($user) {
            return $user;
        }

        // If the user is not authenticated, return the anonymous user.
        return $this->anonymousUser;
    }

    /**
     * Checks if a path is the login route.
     *
     * @param string $path The route path to check.
     * @return bool True if it's the login route, false otherwise.
     */
    protected function isLoginPath(string $path): bool
    {
        return $path === $this->config->getLoginPath();
    }

    /**
     * Checks if a path is the logout route.
     *
     * @param string $path The route path to check.
     * @return bool True if it's the logout route, false otherwise.
     */
    protected function isLogoutPath(string $path): bool
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
     *
     * @param ServerRequestInterface $request The request.
     * @return bool True if it is a logout.
     */
    protected function isLogoutRequest(ServerRequestInterface $request): bool
    {
        return strtoupper($request->getMethod()) === 'POST' && $this->isSameOrigin($request);
    }

    /**
     * Checks if a request comes from the same origin, by what the browser says.
     *
     * @param ServerRequestInterface $request The request.
     * @return bool True if it does, or if it does not say (it is not a browser).
     */
    protected function isSameOrigin(ServerRequestInterface $request): bool
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
     * Handles the logout.
     *
     * @param ServerRequestInterface $request The request.
     * @return PsrResponseInterface The response.
     */
    protected function handleLogout(ServerRequestInterface $request): PsrResponseInterface
    {
        $session = $this->getSessionFromRequest($request);
        if ($session) {
            $this->logout($session);
        }

        $this->addSuccessFlash($request, 'The session has been closed successfully.');

        return new RedirectResponse((string) $this->config->getLogoutRedirectPath());
    }

    /**
     * Handles the unauthorized request (when a session is available).
     *
     * @param ServerRequestInterface $request The request.
     * @param SessionInterface $session The session.
     * @return PsrResponseInterface The response.
     */
    protected function handleUnauthorized(
        ServerRequestInterface $request,
        SessionInterface $session
    ): PsrResponseInterface {
        // Add flash message for authentication requirement.
        $this->addErrorFlash(
            $request,
            'You must be logged in to access the requested page {path}',
            ['path' => $request->getUri()->getPath()]
        );

        return $this->createUnauthorizedResponse($request, $session);
    }

    /**
     * Handles the unauthenticated request (when no session is available).
     *
     * @param ServerRequestInterface $request The request.
     * @return PsrResponseInterface The response.
     */
    protected function handleUnauthenticated(
        ServerRequestInterface $request
    ): PsrResponseInterface {
        $this->addErrorFlash(
            $request,
            'You must be logged in to access the requested page {path}',
            ['path' => $request->getUri()->getPath()]
        );

        return new RedirectResponse((string) $this->config->getUnauthorizedRedirectPath());
    }

    /**
     * Handles the unauthorized request to the API (a path that starts with
     * `/api`): a JSON response with the status 401, in the language of the
     * translator.
     *
     * @return PsrResponseInterface The response.
     */
    protected function handleUnauthorizedApi(): PsrResponseInterface
    {
        return new JsonResponse(
            [
                'status' => 401,
                'title' => $this->translate(new TranslatableMessage('Unauthorized', [], 'auth')),
                'detail' => $this->translate(new TranslatableMessage('You need to send valid credentials to access this resource.', [], 'auth')),
            ],
            401
        );
    }

    /**
     * Translates a message with the translator, if there is one.
     */
    private function translate(TranslatableMessage $message): string
    {
        return $this->translator !== null
            ? $message->trans($this->translator)
            : (string) $message;
    }

    /**
     * Handles the login.
     *
     * @param ServerRequestInterface $request The request.
     * @param SessionInterface $session The session.
     * @return UserInterface|null The user or null if the login fails.
     */
    abstract protected function handleLogin(
        ServerRequestInterface $request,
        SessionInterface $session
    ): ?UserInterface;

    /**
     * Gets the authenticated user from the session.
     *
     * @param SessionInterface $session The session.
     * @return UserInterface|null The user or null if the user is not authenticated.
     */
    abstract protected function getAuthenticatedUserFromSession(
        SessionInterface $session
    ): ?UserInterface;

    /**
     * {@inheritDoc}
     */
    protected function logout(SessionInterface $session): void
    {
        $this->sessionManager->clearSession($session);

        // The identifier that the session had must be of no use after logout.
        $this->sessionManager->regenerate($session);
    }

    /**
     * Remembers the current page, for the redirect after the authentication.
     *
     * Only its path and query are stored, so what is stored never takes the user
     * to another site (the host of a request is not to be trusted).
     */
    protected function rememberPage(ServerRequestInterface $request, SessionInterface $session): void
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

    /**
     * {@inheritDoc}
     */
    protected function createUnauthorizedResponse(
        ServerRequestInterface $request,
        SessionInterface $session
    ): PsrResponseInterface {
        $this->rememberPage($request, $session);

        // Redirect to login page.
        return new RedirectResponse((string) $this->config->getUnauthorizedRedirectPath());
    }
}
