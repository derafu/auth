<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Service;

use Derafu\Auth\Contract\AuthConfigurationInterface;
use Derafu\Auth\Contract\SessionManagerInterface;

/**
 * Session service implementation.
 *
 * This service manages authentication session data using PHP sessions.
 */
class SessionService implements SessionManagerInterface
{
    /**
     * Creates a new session service.
     *
     * @param AuthConfigurationInterface $config The authentication configuration.
     */
    public function __construct(
        private readonly AuthConfigurationInterface $config
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function start(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            // Configure session parameters.
            session_set_cookie_params([
                'lifetime' => $this->config->getSessionLifetime(),
                'path' => '/',
                'secure' => $this->config->getSecureCookies(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);

            session_start();
        }
    }

    /**
     * {@inheritDoc}
     */
    public function storeAuthInfo(
        string $accessToken,
        ?string $refreshToken = null,
        ?int $expiresAt = null
    ): void {
        $this->start();
        $_SESSION['oauth2_token'] = $accessToken;

        if ($refreshToken) {
            $_SESSION['oauth2_refresh_token'] = $refreshToken;
        }

        if ($expiresAt) {
            $_SESSION['oauth2_expiry'] = $expiresAt;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function storeUserInfo(array $userInfo): void
    {
        $this->start();
        $_SESSION['user'] = $userInfo;
    }

    /**
     * {@inheritDoc}
     */
    public function storeState(string $state): void
    {
        $this->start();
        $_SESSION['oauth2_state'] = $state;

        // Also store in cookie as backup.
        setcookie(
            'oauth2_state',
            $state,
            time() + 600,
            '/',
            '',
            $this->config->getSecureCookies(),
            true
        );
    }

    /**
     * {@inheritDoc}
     */
    public function storeRedirectUrl(string $url): void
    {
        $this->start();
        $_SESSION['auth_redirect'] = $url;
    }

    /**
     * {@inheritDoc}
     */
    public function getRedirectUrl(): string
    {
        $this->start();
        $redirect = $_SESSION['auth_redirect'] ?? '/';
        unset($_SESSION['auth_redirect']);

        return $redirect;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAuthInfo(): bool
    {
        $this->start();

        return isset($_SESSION['oauth2_token']);
    }

    /**
     * {@inheritDoc}
     */
    public function isTokenExpired(): bool
    {
        $this->start();

        return isset($_SESSION['oauth2_expiry']) && $_SESSION['oauth2_expiry'] < time();
    }

    /**
     * {@inheritDoc}
     */
    public function getAccessToken(): ?string
    {
        $this->start();

        return $_SESSION['oauth2_token'] ?? null;
    }

    /**
     * {@inheritDoc}
     */
    public function getRefreshToken(): ?string
    {
        $this->start();

        return $_SESSION['oauth2_refresh_token'] ?? null;
    }

    /**
     * {@inheritDoc}
     */
    public function getUserInfo(): ?array
    {
        $this->start();

        return $_SESSION['user'] ?? null;
    }

    /**
     * {@inheritDoc}
     */
    public function getState(): ?string
    {
        $this->start();

        return $_SESSION['oauth2_state'] ?? $_COOKIE['oauth2_state'] ?? null;
    }

    /**
     * {@inheritDoc}
     */
    public function clearState(): void
    {
        $this->start();
        unset($_SESSION['oauth2_state']);

        if (isset($_COOKIE['oauth2_state'])) {
            setcookie('oauth2_state', '', time() - 3600, '/');
        }
    }

    /**
     * {@inheritDoc}
     */
    public function clear(): void
    {
        $this->start();
        unset(
            $_SESSION['oauth2_token'],
            $_SESSION['oauth2_refresh_token'],
            $_SESSION['oauth2_expiry'],
            $_SESSION['user'],
            $_SESSION['oauth2_state'],
            $_SESSION['auth_redirect']
        );

        if (isset($_COOKIE['oauth2_state'])) {
            setcookie('oauth2_state', '', time() - 3600, '/');
        }
    }
}
