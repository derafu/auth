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
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserInterface;
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

        // If the path is not protected, return the user (authenticated or
        // anonymous).
        if (!$this->config->requiresAuth($path)) {
            return $user;
        }

        // If the path is protected, the user must be authenticated.
        if ($user->isAnonymous()) {
            // Must be null to trigger unauthorized response and give an error
            // message.
            return null;
        }

        // Handle logout.
        if ($this->isLogoutPath($path)) {
            if ($session) {
                $this->logout($session);
            }
            // Must be null to trigger unauthorized response and handle logout.
            return null;
        }

        // Handle login.
        if ($this->isLoginPath($path) && $session) {
            return $this->handleLogin($request, $session);
        }

        // The user is authenticated, is not the logout path and is not the
        // login path, so return the user.
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
     * Handles the logout.
     *
     * @param ServerRequestInterface $request The request.
     * @return PsrResponseInterface The response.
     */
    protected function handleLogout(ServerRequestInterface $request): PsrResponseInterface
    {
        $this->addSuccessFlash($request, 'The session has been closed successfully.');

        return new RedirectResponse((string) $this->config->getLogoutRedirectRoute());
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
        $path = $request->getUri()->getPath();

        if (str_starts_with($path, '/api')) {
            return new JsonResponse(
                [
                    'status' => 401,
                    'title' => $this->translate(new TranslatableMessage('Unauthorized', [], 'auth')),
                    'detail' => $this->translate(new TranslatableMessage('You need to send valid credentials to access this resource.', [], 'auth')),
                ],
                401
            );
        }

        $this->addErrorFlash(
            $request,
            'You must be logged in to access the requested page {path}',
            ['path' => $request->getUri()->getPath()]
        );

        return new RedirectResponse((string) $this->config->getUnauthorizedRedirectRoute());
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
    }

    /**
     * {@inheritDoc}
     */
    protected function createUnauthorizedResponse(
        ServerRequestInterface $request,
        SessionInterface $session
    ): PsrResponseInterface {
        // Store current URL for redirect after authentication.
        $this->sessionManager->storeRedirectUrl($session, (string) $request->getUri());

        // Redirect to login page.
        return new RedirectResponse((string) $this->config->getUnauthorizedRedirectRoute());
    }
}
