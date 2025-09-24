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

use Derafu\Auth\Abstract\AbstractProviderAuthentication;
use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Keycloak authentication implementation for Mezzio.
 *
 * This class implements our AuthenticationInterface to provide
 * OAuth2/OpenID Connect authentication with Keycloak.
 */
class KeycloakAuthentication extends AbstractProviderAuthentication implements AuthenticationInterface
{
    /**
     * Creates a new Keycloak authentication implementation.
     *
     * @param KeycloakUserRepository $userRepository The user repository.
     * @param KeycloakConfiguration $config The configuration.
     * @param KeycloakSessionManager $sessionManager The session manager.
     * @param UserInterface $anonymousUser The anonymous user.
     */
    public function __construct(
        private readonly KeycloakUserRepository $userRepository,
        KeycloakConfiguration $config,
        private readonly KeycloakSessionManager $sessionManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser()
    ) {
        parent::__construct(
            config: $config,
            sessionManager: $sessionManager,
            anonymousUser: $anonymousUser
        );
    }

    /**
     * {@inheritDoc}
     */
    protected function handleLogin(
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
     * {@inheritDoc}
     */
    protected function getAuthenticatedUserFromSession(SessionInterface $session): ?UserInterface
    {
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

        // If the user info is not found, return null.
        return null;
    }

    /**
     * {@inheritDoc}
     */
    protected function createUnauthorizedResponse(
        ServerRequestInterface $request,
        SessionInterface $session
    ): PsrResponseInterface {
        // Add flash message for authentication requirement.
        $this->addErrorFlash($request, 'You must be logged in to access the requested page.');

        // Store current URL for redirect after authentication.
        $this->sessionManager->storeRedirectUrl($session, (string) $request->getUri());

        // Generate authorization URL.
        $authUrl = $this->userRepository->createAuthorizationUrl();

        // Store state for CSRF protection.
        $state = $this->userRepository->getState();
        $this->sessionManager->storeState($session, $state);

        return new RedirectResponse($authUrl);
    }
}
