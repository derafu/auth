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

use Mezzio\Session\SessionInterface;

/**
 * Keycloak session management.
 *
 * Handles OAuth2 session data storage and retrieval for Keycloak.
 */
class KeycloakSessionManager
{
    /**
     * Stores authentication information in the session.
     *
     * @param SessionInterface $session The session to store the info in.
     * @param array<string, mixed> $tokenInfo The token information to store.
     */
    public function storeAuthInfo(SessionInterface $session, array $tokenInfo): void
    {
        $session->set('oauth2_token', $tokenInfo['access_token']);
        if (isset($tokenInfo['refresh_token'])) {
            $session->set('oauth2_refresh_token', $tokenInfo['refresh_token']);
        }
        if (isset($tokenInfo['expires'])) {
            $session->set('oauth2_expiry', $tokenInfo['expires']);
        }
    }

    /**
     * Stores user information in the session.
     *
     * @param SessionInterface $session The session to store the info in.
     * @param array<string, mixed> $userInfo The user information to store.
     */
    public function storeUserInfo(SessionInterface $session, array $userInfo): void
    {
        $session->set('user', $userInfo);
    }

    /**
     * Gets the stored user information from the session.
     *
     * @param SessionInterface $session The session to get the info from.
     * @return array<string, mixed>|null The user information or null if not found.
     */
    public function getUserInfo(SessionInterface $session): ?array
    {
        return $session->get('user');
    }

    /**
     * Checks if authentication information exists in the session.
     *
     * @param SessionInterface $session The session to check.
     * @return bool True if auth info exists, false otherwise.
     */
    public function hasAuthInfo(SessionInterface $session): bool
    {
        return $session->has('oauth2_token');
    }

    /**
     * Checks if the stored token has expired.
     *
     * @param SessionInterface $session The session to check.
     * @return bool True if token has expired, false otherwise.
     */
    public function isTokenExpired(SessionInterface $session): bool
    {
        return $session->has('oauth2_expiry') && $session->get('oauth2_expiry') < time();
    }

    /**
     * Gets the stored refresh token from the session.
     *
     * @param SessionInterface $session The session to get the token from.
     * @return string|null The refresh token or null if not found.
     */
    public function getRefreshToken(SessionInterface $session): ?string
    {
        return $session->get('oauth2_refresh_token');
    }

    /**
     * Stores the state parameter for CSRF protection.
     *
     * @param SessionInterface $session The session to store the state in.
     * @param string $state The state parameter to store.
     */
    public function storeState(SessionInterface $session, string $state): void
    {
        $session->set('oauth2_state', $state);
    }

    /**
     * Gets the stored state parameter from the session.
     *
     * @param SessionInterface $session The session to get the state from.
     * @return string|null The state parameter or null if not found.
     */
    public function getState(SessionInterface $session): ?string
    {
        return $session->get('oauth2_state');
    }

    /**
     * Clears the stored state parameter from the session.
     *
     * @param SessionInterface $session The session to clear the state from.
     */
    public function clearState(SessionInterface $session): void
    {
        $session->unset('oauth2_state');
    }

    /**
     * Stores the redirect URL for after authentication.
     *
     * @param SessionInterface $session The session to store the URL in.
     * @param string $url The redirect URL to store.
     */
    public function storeRedirectUrl(SessionInterface $session, string $url): void
    {
        $session->set('auth_redirect', $url);
    }

    /**
     * Gets the stored redirect URL.
     *
     * @param SessionInterface $session The session to get the URL from.
     * @return string|null The redirect URL or null if not found.
     */
    public function getRedirectUrl(SessionInterface $session): ?string
    {
        return $session->get('auth_redirect');
    }

    /**
     * Clears all authentication information from the session.
     *
     * @param SessionInterface $session The session to clear.
     */
    public function clearSession(SessionInterface $session): void
    {
        $session->unset('oauth2_token');
        $session->unset('oauth2_refresh_token');
        $session->unset('oauth2_expiry');
        $session->unset('user');
        $session->unset('oauth2_state');
        $session->unset('auth_redirect');
    }
}
