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
use Derafu\Auth\Contract\UserRepositoryInterface;
use Derafu\Auth\LoginThrottle;
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

        // A client of the API that sends credentials in the header
        // `Authorization` (of the scheme that the provider reads) is
        // authenticated by them, in each request and without a session: the
        // session is not read, so nothing is kept and no cookie is set. If they
        // are not valid it is not authenticated: it does not go back to a session
        // that it may have, it was not asking for one.
        $credentials = $this->credentialsOf($request);
        $user = $credentials !== null
            ? $this->authenticateCredentials($request, $credentials) ?? $this->anonymousUser
            : $this->getUserFromSession($session);

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
        if ($this->isApiPath($path)) {
            return $this->handleUnauthorizedApi($request);
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
     * Handles the unauthorized request to the API (a path that is one of the ones of
     * the API or below one of them): a JSON response with the status 401, in the language of
     * the translator, and the header `WWW-Authenticate` that says how to
     * authenticate (see `challenge()`).
     *
     * @param ServerRequestInterface|null $request The request, to know whether
     * it sent credentials that were not valid.
     * @return PsrResponseInterface The response.
     */
    protected function handleUnauthorizedApi(?ServerRequestInterface $request = null): PsrResponseInterface
    {
        $challenge = $request !== null ? $this->challenge($request) : null;

        return new JsonResponse(
            [
                'status' => 401,
                'title' => $this->translate(new TranslatableMessage('Unauthorized', [], 'auth')),
                'detail' => $this->translate(new TranslatableMessage('You need to send valid credentials to access this resource.', [], 'auth')),
            ],
            401,
            $challenge !== null ? ['WWW-Authenticate' => $challenge] : []
        );
    }

    /**
     * Gets the scheme of the header `Authorization` that the provider reads from
     * a client of the API (`Bearer` for a token, `Basic` for a user and a
     * password), or null if it reads none: the credentials are not read from the
     * header, and a header is ignored.
     *
     * A header with another scheme is ignored too, not rejected: a server that is
     * in front of the application can add its own (a `Basic` for the whole
     * site), and that must not break the sessions of the users.
     *
     * @return string|null The scheme.
     */
    protected function authorizationScheme(): ?string
    {
        return null;
    }

    /**
     * Authenticates a client of the API by the credentials that it sent in the
     * header `Authorization`, with the scheme that the provider reads
     * (`authorizationScheme()`). It is done in each request, and nothing is kept.
     *
     * @param ServerRequestInterface $request The request.
     * @param string $credentials What comes after the scheme: the token, or the
     * user and the password in Base64.
     * @return UserInterface|null The user, or null if the credentials are not
     * valid.
     */
    protected function authenticateCredentials(
        ServerRequestInterface $request,
        string $credentials
    ): ?UserInterface {
        return null;
    }

    /**
     * Gets the credentials that a request sends in the header `Authorization`,
     * if they are for the API and of the scheme that the provider reads.
     *
     * @param ServerRequestInterface $request The request.
     * @return string|null What comes after the scheme, or null if there are none.
     */
    protected function credentialsOf(ServerRequestInterface $request): ?string
    {
        $scheme = $this->authorizationScheme();
        if ($scheme === null || !$this->isApiPath($request->getUri()->getPath())) {
            return null;
        }

        // `Scheme credentials`, in one header: two of them, or a scheme with
        // nothing after it, are not credentials.
        $header = trim($request->getHeaderLine('Authorization'));
        if (preg_match('/^(\S+)[ \t]+(\S+)$/', $header, $matches) && strcasecmp($matches[1], $scheme) === 0) {
            return $matches[2];
        }

        return null;
    }

    /**
     * Gets what the response 401 of the API says in the header
     * `WWW-Authenticate`: how to authenticate (RFC 7235). For `Bearer` (RFC 6750)
     * it also says `invalid_token` when the request sent a token that was not
     * valid.
     *
     * The challenge of `Basic` is left out when the request says that it comes
     * from a script of a page (`X-Requested-With: XMLHttpRequest`): a browser
     * answers it with its own window to ask for a user and a password, and a page
     * that calls the API with its session wants the `401`, not that window (Rails
     * and Spring do the same). `Bearer` is never asked by a browser, so it is
     * always sent.
     *
     * @param ServerRequestInterface $request The request.
     * @return string|null The challenge, or null if the provider reads no
     * credentials from the header, or if it is not to be sent.
     */
    protected function challenge(ServerRequestInterface $request): ?string
    {
        $scheme = $this->authorizationScheme();
        if ($scheme === null) {
            return null;
        }

        $realm = $this->config->getApiRealm();

        if (strcasecmp($scheme, 'Bearer') === 0) {
            return sprintf('%s realm="%s"', $scheme, $realm)
                . ($this->credentialsOf($request) !== null ? ', error="invalid_token"' : '')
            ;
        }

        if (strcasecmp($request->getHeaderLine('X-Requested-With'), 'XMLHttpRequest') === 0) {
            return null;
        }

        return sprintf('%s realm="%s", charset="UTF-8"', $scheme, $realm);
    }

    /**
     * Reads the credentials of the scheme `Basic` (RFC 7617): the user and the
     * password, separated by a colon, in Base64 and in UTF-8.
     *
     * @param string $credentials What comes after `Basic`.
     * @return array{string, string}|null The identity and the password, or null
     * if it is not Base64, it is not UTF-8, it has no colon or its identity is
     * empty.
     */
    protected function basicCredentials(string $credentials): ?array
    {
        $decoded = base64_decode($credentials, true);
        if ($decoded === false || !mb_check_encoding($decoded, 'UTF-8')) {
            return null;
        }

        $parts = explode(':', $decoded, 2);
        if (count($parts) !== 2 || $parts[0] === '') {
            return null;
        }

        return [$parts[0], $parts[1]];
    }

    /**
     * Authenticates a client of the API by the credentials of the scheme `Basic`
     * (the user and the password), against the repository of users of a provider
     * that has a password for each user.
     *
     * The failed attempts are limited as the ones of the login form are, by
     * identity and by network of the client (see `clientAddress()`): a program
     * guesses passwords much faster than a person. A client that is limited is
     * not asked anything, whatever it sent, so a password that is guessed while
     * it is limited is of no use. The user that does not exist, the one that has
     * a wrong password and the one that is not active are the same answer.
     *
     * The password is verified in each request, as it is in the login (with the
     * cost of the hash of the password): it is the price of not keeping anything.
     *
     * @param ServerRequestInterface $request The request.
     * @param string $credentials What comes after `Basic`.
     * @param UserRepositoryInterface $repository Where the users are.
     * @param LoginThrottle|null $throttle Limits the failed attempts. Without it
     * they are not limited.
     * @return UserInterface|null The user, or null if the credentials are not
     * valid or the client is limited.
     */
    protected function authenticateBasic(
        ServerRequestInterface $request,
        string $credentials,
        UserRepositoryInterface $repository,
        ?LoginThrottle $throttle
    ): ?UserInterface {
        $basic = $this->basicCredentials($credentials);
        if ($basic === null) {
            return null;
        }

        [$identity, $password] = $basic;
        $address = $this->clientAddress($request);

        if (($throttle?->retryAfter($identity, $address) ?? 0) > 0) {
            return null;
        }

        $user = $repository->authenticate($identity, $password);
        if (!$user instanceof UserInterface) {
            $throttle?->hit($identity, $address);

            return null;
        }

        $throttle?->clear($identity, $address);

        return $user;
    }

    /**
     * Checks that a path is one of the API or is below one of them.
     *
     * @param string $path The path.
     * @return bool True if it is.
     */
    protected function isApiPath(string $path): bool
    {
        foreach ($this->config->getApiPaths() as $apiPath) {
            if (Url::pathStartsWith($path, $apiPath)) {
                return true;
            }
        }

        return false;
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
