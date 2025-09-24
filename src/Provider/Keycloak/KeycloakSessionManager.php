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

use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\SessionManager;
use Mezzio\Session\SessionInterface;

/**
 * Keycloak session management.
 *
 * Handles OAuth2 session data storage and retrieval for Keycloak.
 */
class KeycloakSessionManager extends SessionManager implements SessionManagerInterface
{
    /**
     * {@inheritDoc}
     */
    public function hasAuthInfo(SessionInterface $session): bool
    {
        return $session->has('oauth2_token');
    }

    /**
     * {@inheritDoc}
     */
    public function clearSession(SessionInterface $session): void
    {
        $session->unset('oauth2_token');
        $session->unset('oauth2_refresh_token');
        $session->unset('oauth2_expiry');
        $session->unset('oauth2_state');
        $this->clearUserInfo($session);
        $this->clearRedirectUrl($session);
    }

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
}
