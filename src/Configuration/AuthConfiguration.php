<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Configuration;

use Derafu\Auth\Contract\AuthConfigurationInterface;

/**
 * Configuration class for authentication settings.
 */
class AuthConfiguration implements AuthConfigurationInterface
{
    /**
     * Creates a new authentication configuration.
     *
     * @param string $keycloakUrl The Keycloak URL.
     * @param string $realm The Keycloak realm.
     * @param string $clientId The client ID.
     * @param string $clientSecret The client secret.
     * @param string $redirectUri The redirect URI.
     * @param array $scopes The OAuth scopes.
     * @param array $protectedRoutes The protected routes.
     * @param string $callbackRoute The callback route.
     * @param string $logoutRoute The logout route.
     * @param int $sessionLifetime The session lifetime.
     * @param bool $secureCookies Whether to use secure cookies.
     * @param array $httpClientOptions The HTTP client options.
     */
    public function __construct(
        private string $keycloakUrl = '',
        private string $realm = 'master',
        private string $clientId = '',
        private string $clientSecret = '',
        private string $redirectUri = '',
        private array $scopes = ['openid', 'profile', 'email'],
        private array $protectedRoutes = ['/dashboard', '/profile', '/admin'],
        private string $callbackRoute = '/auth/callback',
        private string $logoutRoute = '/auth/logout',
        private int $sessionLifetime = 3600,
        private bool $secureCookies = false,
        private array $httpClientOptions = [
            'timeout' => 30,
            'connect_timeout' => 30,
            'verify' => false,
        ],
    ) {
    }

    /**
     * Gets the Keycloak URL.
     *
     * @return string The Keycloak URL.
     */
    public function getKeycloakUrl(): string
    {
        return $this->keycloakUrl;
    }

    /**
     * Gets the Keycloak realm.
     *
     * @return string The Keycloak realm.
     */
    public function getRealm(): string
    {
        return $this->realm;
    }

    /**
     * Gets the client ID.
     *
     * @return string The client ID.
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * Gets the client secret.
     *
     * @return string The client secret.
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * Gets the redirect URI.
     *
     * @return string The redirect URI.
     */
    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    /**
     * Gets the OAuth scopes.
     *
     * @return array<string> The OAuth scopes.
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * Gets the protected routes.
     *
     * @return array<string> The protected routes.
     */
    public function getProtectedRoutes(): array
    {
        return $this->protectedRoutes;
    }

    /**
     * Gets the callback route.
     *
     * @return string The callback route.
     */
    public function getCallbackRoute(): string
    {
        return $this->callbackRoute;
    }

    /**
     * Gets the logout route.
     *
     * @return string The logout route.
     */
    public function getLogoutRoute(): string
    {
        return $this->logoutRoute;
    }

    /**
     * Gets the session lifetime in seconds.
     *
     * @return int The session lifetime.
     */
    public function getSessionLifetime(): int
    {
        return $this->sessionLifetime;
    }

    /**
     * Gets whether HTTPS is required for cookies.
     *
     * @return bool True if HTTPS is required, false otherwise.
     */
    public function isSecureCookies(): bool
    {
        return $this->secureCookies;
    }

    /**
     * Gets whether to use secure cookies.
     *
     * @return bool True if secure cookies should be used.
     */
    public function getSecureCookies(): bool
    {
        return $this->secureCookies;
    }

    /**
     * Gets the HTTP client options.
     *
     * @return array The HTTP client options.
     */
    public function getHttpClientOptions(): array
    {
        return $this->httpClientOptions;
    }

    /**
     * Gets all configuration as an array.
     *
     * @return array The configuration array.
     */
    public function toArray(): array
    {
        return [
            'keycloak_url' => $this->keycloakUrl,
            'realm' => $this->realm,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'protected_routes' => $this->protectedRoutes,
            'callback_route' => $this->callbackRoute,
            'logout_route' => $this->logoutRoute,
            'session_lifetime' => $this->sessionLifetime,
            'secure_cookies' => $this->secureCookies,
            'http_client_options' => $this->httpClientOptions,
        ];
    }
}
