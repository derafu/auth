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
        $session->unset('oauth2_id_token');
        $this->clearState($session);
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
        if (isset($tokenInfo['id_token'])) {
            $session->set('oauth2_id_token', $tokenInfo['id_token']);
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
     * Stores what the login needs to be finished when the user comes back from
     * Keycloak: the nonce that the ID token must have and the PKCE code (the
     * verifier of the challenge that was sent). The state is stored with
     * `storeState()`.
     *
     * @param SessionInterface $session The session.
     * @param string $nonce The nonce of the authorization URL.
     * @param string|null $pkceCode The PKCE code of the authorization URL.
     */
    public function storeLogin(SessionInterface $session, string $nonce, ?string $pkceCode): void
    {
        $session->set('oauth2_nonce', $nonce);
        $session->set('oauth2_pkce', $pkceCode);
    }

    /**
     * Gets the nonce of the login that is in progress.
     *
     * @param SessionInterface $session The session.
     * @return string|null The nonce or null if there is no login in progress.
     */
    public function getNonce(SessionInterface $session): ?string
    {
        return $session->get('oauth2_nonce');
    }

    /**
     * Gets the PKCE code (the verifier) of the login that is in progress.
     *
     * @param SessionInterface $session The session.
     * @return string|null The PKCE code.
     */
    public function getPkceCode(SessionInterface $session): ?string
    {
        return $session->get('oauth2_pkce');
    }

    /**
     * Gets the ID token of the session: what Keycloak needs to end the session
     * of the user.
     *
     * @param SessionInterface $session The session.
     * @return string|null The ID token.
     */
    public function getIdToken(SessionInterface $session): ?string
    {
        return $session->get('oauth2_id_token');
    }

    /**
     * Clears what the login in progress stored: the state, the nonce and the PKCE
     * code.
     *
     * @param SessionInterface $session The session to clear.
     */
    public function clearState(SessionInterface $session): void
    {
        $session->unset('oauth2_state');
        $session->unset('oauth2_nonce');
        $session->unset('oauth2_pkce');
    }
}
