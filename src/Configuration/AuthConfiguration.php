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
use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration class for authentication settings.
 */
class AuthConfiguration implements AuthConfigurationInterface
{
    /**
     * The Keycloak URL.
     *
     * @var string
     */
    private string $keycloakUrl;

    /**
     * The Keycloak realm.
     *
     * @var string
     */
    private string $realm = 'master';

    /**
     * The client ID.
     *
     * @var string
     */
    private string $clientId;

    /**
     * The client secret.
     *
     * @var string
     */
    private string $clientSecret;

    /**
     * The redirect URI.
     *
     * @var string
     */
    private string $redirectUri;

    /**
     * The OAuth scopes.
     *
     * @var array<string>
     */
    private array $scopes = ['openid', 'profile', 'email'];

    /**
     * The protected routes.
     *
     * @var array<string>
     */
    private array $protectedRoutes = ['/dashboard', '/profile', '/admin'];

    /**
     * The callback route.
     *
     * @var string
     */
    private string $callbackRoute = '/auth/callback';

    /**
     * The logout route.
     *
     * @var string
     */
    private string $logoutRoute = '/auth/logout';

    /**
     * The session lifetime.
     *
     * @var int
     */
    private int $sessionLifetime = 3600;

    /**
     * Whether to use secure cookies.
     *
     * @var bool
     */
    private bool $secureCookies = false;

    /**
     * The HTTP client options.
     *
     * @var array
     */
    private array $httpClientOptions = [
        'timeout' => 30,
        'connect_timeout' => 30,
        'verify' => false,
    ];

    /**
     * Creates a new authentication configuration.
     *
     * @param array $config The configuration array.
     */
    public function __construct(array $config = [])
    {
        if (empty($config['keycloak_url'])) {
            throw new ConfigurationException('Keycloak URL is required.');
        }
        $this->keycloakUrl = $config['keycloak_url'];

        if (!empty($config['realm'])) {
            $this->realm = $config['realm'];
        }

        if (empty($config['client_id'])) {
            throw new ConfigurationException('Client ID is required.');
        }
        $this->clientId = $config['client_id'];

        if (empty($config['client_secret'])) {
            throw new ConfigurationException('Client secret is required.');
        }
        $this->clientSecret = $config['client_secret'];

        if (empty($config['redirect_uri'])) {
            throw new ConfigurationException('Redirect URI is required.');
        }
        $this->redirectUri = $config['redirect_uri'];

        if (!empty($config['scopes'])) {
            $this->scopes = $config['scopes'];
        }

        if (!empty($config['protected_routes'])) {
            $this->protectedRoutes = $config['protected_routes'];
        }

        if (!empty($config['callback_route'])) {
            $this->callbackRoute = $config['callback_route'];
        }

        if (!empty($config['logout_route'])) {
            $this->logoutRoute = $config['logout_route'];
        }

        if (!empty($config['session_lifetime'])) {
            $this->sessionLifetime = $config['session_lifetime'];
        }

        if (isset($config['secure_cookies'])) {
            $this->secureCookies = $config['secure_cookies'];
        }

        if (!empty($config['http_client_options']['timeout'])) {
            $this->httpClientOptions['timeout'] = $config['http_client_options']['timeout'];
        }

        if (!empty($config['http_client_options']['connect_timeout'])) {
            $this->httpClientOptions['connect_timeout'] = $config['http_client_options']['connect_timeout'];
        }

        if (isset($config['http_client_options']['verify'])) {
            $this->httpClientOptions['verify'] = $config['http_client_options']['verify'];
        }
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
