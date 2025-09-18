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

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Keycloak authentication implementation for Mezzio.
 *
 * This class implements our AuthenticationInterface to provide
 * OAuth2/OpenID Connect authentication with Keycloak.
 */
final class KeycloakAuthentication implements AuthenticationInterface
{
    /**
     * Creates a new Keycloak authentication implementation.
     *
     * @param KeycloakUserRepository $userRepository The user repository.
     */
    public function __construct(
        private readonly KeycloakUserRepository $userRepository,
        private readonly KeycloakConfiguration $config,
        private readonly KeycloakSessionManager $sessionManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser()
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

        // If the path is not protected, return the user (authenticated or anonymous).
        if (!$this->config->requiresAuth($path)) {
            return $user;
        }

        // If the path is protected, the user must be authenticated.
        if ($user->isAnonymous()) {
            return null; // Must be null to trigger unauthorized response and give an error message.
        }

        // Handle logout.
        if ($this->isLogoutPath($path)) {
            if ($session) {
                $this->sessionManager->clearSession($session);
            }
            return null; // Must be null to trigger unauthorized response and handle logout.
        }

        // Handle authentication callback.
        if ($this->isCallbackPath($path) && $session) {
            return $this->handleCallback($request, $session);
        }

        // If the user is authenticated, return the user.
        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function unauthorizedResponse(
        ServerRequestInterface $request
    ): ResponseInterface {
        $path = $request->getUri()->getPath();
        $session = $this->getSessionFromRequest($request);

        // Handle logout - redirect to home.
        if ($this->isLogoutPath($path)) {
            $flash = $this->getFlashFromRequest($request);
            if ($flash && method_exists($flash, 'flash')) {
                $flash->flash('success', 'The session has been closed successfully.');
            }
            return new RedirectResponse((string) $this->config->getLogoutRedirectRoute());
        }

        if ($session) {
            // Add flash message for authentication requirement.
            $flash = $this->getFlashFromRequest($request);
            if ($flash && method_exists($flash, 'flash')) {
                $flash->flash('error', 'You must be logged in to access the requested page.');
            }

            // Store current URL for redirect after authentication.
            $this->sessionManager->storeRedirectUrl($session, (string) $request->getUri());

            // Generate authorization URL.
            $authUrl = $this->userRepository->createAuthorizationUrl();

            // Store state for CSRF protection.
            $state = $this->userRepository->getState();
            $this->sessionManager->storeState($session, $state);

            return new RedirectResponse($authUrl);
        }

        if (str_starts_with($path, '/api')) {
            return new JsonResponse(['error' => 'Unauthorized.'], 401);
        }

        $flash = $this->getFlashFromRequest($request);
        if ($flash && method_exists($flash, 'flash')) {
            $flash->flash('error', 'You must be logged in to access the requested page.');
        }

        return new RedirectResponse((string) $this->config->getUnauthorizedRedirectRoute());
    }

    /**
     * Gets flash messages from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return mixed The flash messages or null if not available.
     */
    private function getFlashFromRequest(ServerRequestInterface $request): mixed
    {
        return $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE);
    }

    /**
     * Gets the session from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return SessionInterface|null The session or null if not found.
     */
    private function getSessionFromRequest(ServerRequestInterface $request): ?SessionInterface
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
    private function getUserFromSession(?SessionInterface $session): UserInterface
    {
        // If there is no session, return the anonymous user.
        if (!$session) {
            return $this->anonymousUser;
        }

        // Check if user is already authenticated.
        if ($this->sessionManager->hasAuthInfo($session)) {
            // Check if token has expired.
            if ($this->sessionManager->isTokenExpired($session)) {
                $refreshToken = $this->sessionManager->getRefreshToken($session);
                if ($refreshToken) {
                    try {
                        $tokenInfo = $this->userRepository->refreshToken($refreshToken);
                        $this->sessionManager->storeAuthInfo($session, $tokenInfo);

                        // Get updated user info.
                        $userInfo = $this->userRepository->getUserInfoFromToken(
                            $tokenInfo['access_token']
                        );
                        $this->sessionManager->storeUserInfo($session, $userInfo);

                        return new KeycloakUser($userInfo);
                    } catch (AuthenticationException) {
                        $this->sessionManager->clearSession($session);
                        return $this->anonymousUser;
                    }
                } else {
                    $this->sessionManager->clearSession($session);
                    return $this->anonymousUser;
                }
            }

            // Return existing user.
            $userInfo = $this->sessionManager->getUserInfo($session);
            if ($userInfo) {
                return new KeycloakUser($userInfo);
            }
        }

        return $this->anonymousUser;
    }

    /**
     * Handles the authentication callback.
     *
     * @param ServerRequestInterface $request The request.
     * @param SessionInterface $session The session.
     * @return UserInterface|null The authenticated user or null.
     */
    private function handleCallback(
        ServerRequestInterface $request,
        SessionInterface $session
    ): ?UserInterface {
        $queryParams = $request->getQueryParams();
        $savedState = $this->sessionManager->getState($session);

        // Verify state parameter for CSRF protection.
        if (!isset($queryParams['state']) || $savedState !== $queryParams['state']) {
            $this->sessionManager->clearState($session);
            return null;
        }

        // Process authorization code.
        if (!isset($queryParams['code'])) {
            return null;
        }

        try {
            // Exchange code for token.
            $tokenInfo = $this->userRepository->exchangeCodeForToken($queryParams['code']);

            // Store authentication information.
            $this->sessionManager->storeAuthInfo($session, $tokenInfo);

            // Get and store user information.
            $userInfo = $this->userRepository->getUserInfoFromToken($tokenInfo['access_token']);
            $this->sessionManager->storeUserInfo($session, $userInfo);

            // Clear state.
            $this->sessionManager->clearState($session);

            return new KeycloakUser($userInfo);

        } catch (AuthenticationException) {
            return null;
        }
    }

    /**
     * Checks if a path is the authentication callback route.
     *
     * @param string $path The route path to check.
     * @return bool True if it's the callback route, false otherwise.
     */
    private function isCallbackPath(string $path): bool
    {
        return $path === $this->config->getCallbackRoute();
    }

    /**
     * Checks if a path is the logout route.
     *
     * @param string $path The route path to check.
     * @return bool True if it's the logout route, false otherwise.
     */
    private function isLogoutPath(string $path): bool
    {
        return $path === $this->config->getLogoutRoute();
    }
}
