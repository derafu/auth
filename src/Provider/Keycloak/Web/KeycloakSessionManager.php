<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak\Web;

use Derafu\Array\ArrayReader;
use Derafu\Auth\Authentication\Channel\Web\SessionManager;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Contract\KeycloakSessionManagerInterface;
use Mezzio\Session\SessionInterface;

/**
 * Keycloak session management.
 *
 * Handles OAuth2 session data storage and retrieval for Keycloak.
 */
class KeycloakSessionManager extends SessionManager implements KeycloakSessionManagerInterface
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
     * {@inheritDoc}
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
        // The expiry of this token, and no other: the one of the token before it
        // is of no use (it is in the past, and every request would ask again).
        if (isset($tokenInfo['expires'])) {
            $session->set('oauth2_expiry', $tokenInfo['expires']);
        } else {
            $session->unset('oauth2_expiry');
        }
    }

    /**
     * {@inheritDoc}
     */
    public function isTokenExpired(SessionInterface $session): bool
    {
        return $session->has('oauth2_expiry') && $session->get('oauth2_expiry') < time();
    }

    /**
     * {@inheritDoc}
     *
     * The token expires, and that is when the user is asked again, unless the
     * interval says earlier: what happens first. A token without an expiry has
     * the interval, and the default one if there is none, so it is never left
     * without being asked again.
     */
    public function isRefreshDue(SessionInterface $session, ?int $interval): bool
    {
        if ($this->isTokenExpired($session)) {
            return true;
        }

        $interval ??= $session->has('oauth2_expiry') ? null : WebConfiguration::DEFAULT_REFRESH_INTERVAL;

        return parent::isRefreshDue($session, $interval);
    }

    /**
     * {@inheritDoc}
     */
    public function getRefreshToken(SessionInterface $session): ?string
    {
        return ArrayReader::fromArray(['oauth2_refresh_token' => $session->get('oauth2_refresh_token')])
            ->getString('oauth2_refresh_token');
    }

    /**
     * {@inheritDoc}
     */
    public function storeState(SessionInterface $session, string $state): void
    {
        $session->set('oauth2_state', $state);
    }

    /**
     * {@inheritDoc}
     */
    public function getState(SessionInterface $session): ?string
    {
        return ArrayReader::fromArray(['oauth2_state' => $session->get('oauth2_state')])
            ->getString('oauth2_state');
    }

    /**
     * {@inheritDoc}
     */
    public function storeLogin(SessionInterface $session, string $nonce, ?string $pkceCode): void
    {
        $session->set('oauth2_nonce', $nonce);
        $session->set('oauth2_pkce', $pkceCode);
    }

    /**
     * {@inheritDoc}
     */
    public function getNonce(SessionInterface $session): ?string
    {
        return ArrayReader::fromArray(['oauth2_nonce' => $session->get('oauth2_nonce')])
            ->getString('oauth2_nonce');
    }

    /**
     * {@inheritDoc}
     */
    public function getPkceCode(SessionInterface $session): ?string
    {
        return ArrayReader::fromArray(['oauth2_pkce' => $session->get('oauth2_pkce')])
            ->getString('oauth2_pkce');
    }

    /**
     * {@inheritDoc}
     */
    public function getIdToken(SessionInterface $session): ?string
    {
        return ArrayReader::fromArray(['oauth2_id_token' => $session->get('oauth2_id_token')])
            ->getString('oauth2_id_token');
    }

    /**
     * {@inheritDoc}
     */
    public function getAccessToken(SessionInterface $session): ?string
    {
        $token = $session->get('oauth2_token');

        return is_string($token) ? $token : null;
    }

    /**
     * {@inheritDoc}
     */
    public function clearState(SessionInterface $session): void
    {
        $session->unset('oauth2_state');
        $session->unset('oauth2_nonce');
        $session->unset('oauth2_pkce');
    }
}
