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

use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration class for Keycloak authentication settings.
 */
class KeycloakConfiguration implements ConfigurationInterface
{
    private string $keycloakUrl;

    private string $realm;

    private string $clientId;

    private string $clientSecret;

    private string $redirectUri;

    private array $scopes;

    private array $protectedRoutes;

    private string $callbackRoute;

    private string $logoutRoute;

    private string $loginRedirectRoute;

    private string $logoutRedirectRoute;

    private string $unauthorizedRedirectRoute;

    private int $sessionLifetime;

    private bool $secureCookies;

    private array $httpClientOptions;

    private bool $enabled;

    /**
     * Creates a new Keycloak configuration.
     *
     * @param array<string, mixed> $config The configuration array.
     */
    public function __construct(array $config)
    {
        $this->keycloakUrl = $config['keycloak_url']
            ?? $config['keycloakUrl']
            ?? ''
        ;
        $this->realm = $config['realm']
            ?? 'master'
        ;
        $this->clientId = $config['client_id']
            ?? $config['clientId']
            ?? ''
        ;
        $this->clientSecret = $config['client_secret']
            ?? $config['clientSecret']
            ?? ''
        ;
        $this->redirectUri = $config['redirect_uri']
            ?? $config['redirectUri']
            ?? ''
        ;
        $this->scopes = $config['scopes']
            ?? ['openid', 'profile', 'email']
        ;
        $this->protectedRoutes = $config['protected_routes']
            ?? $config['protectedRoutes']
            ?? ['/dashboard', '/profile', '/admin']
        ;
        $this->callbackRoute = $config['callback_route']
            ?? $config['callbackRoute']
            ?? '/auth/callback'
        ;
        $this->logoutRoute = $config['logout_route']
            ?? $config['logoutRoute']
            ?? '/auth/logout'
        ;
        $this->loginRedirectRoute = $config['login_redirect_route']
            ?? $config['loginRedirectRoute']
            ?? '/'
        ;
        $this->logoutRedirectRoute = $config['logout_redirect_route']
            ?? $config['logoutRedirectRoute']
            ?? '/'
        ;
        $this->unauthorizedRedirectRoute = $config['unauthorized_redirect_route']
            ?? $config['unauthorizedRedirectRoute']
            ?? '/'
        ;
        $this->sessionLifetime = $config['session_lifetime']
            ?? $config['sessionLifetime']
            ?? 3600
        ;
        $this->secureCookies = $config['secure_cookies']
            ?? $config['secureCookies']
            ?? false
        ;
        $this->httpClientOptions = $config['http_client_options']
            ?? $config['httpClientOptions']
            ?? [
                'timeout' => 30,
                'connect_timeout' => 30,
                'verify' => false,
            ]
        ;
        $this->enabled = $config['enabled']
            ?? $config['enabled']
            ?? true
        ;
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        if (empty($this->keycloakUrl)) {
            throw new ConfigurationException('Keycloak URL is required.');
        }

        if (empty($this->realm)) {
            throw new ConfigurationException('Keycloak realm is required.');
        }

        if (empty($this->clientId)) {
            throw new ConfigurationException('Client ID is required.');
        }

        if (empty($this->clientSecret)) {
            throw new ConfigurationException('Client secret is required.');
        }

        if (empty($this->redirectUri)) {
            throw new ConfigurationException('Redirect URI is required.');
        }
    }

    /**
     * {@inheritDoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return match ($key) {
            'keycloak_url', 'keycloakUrl' => $this->keycloakUrl,
            'realm' => $this->realm,
            'client_id', 'clientId' => $this->clientId,
            'client_secret', 'clientSecret' => $this->clientSecret,
            'redirect_uri', 'redirectUri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'protected_routes', 'protectedRoutes' => $this->protectedRoutes,
            'callback_route', 'callbackRoute' => $this->callbackRoute,
            'logout_route', 'logoutRoute' => $this->logoutRoute,
            'login_redirect_route', 'loginRedirectRoute' => $this->loginRedirectRoute,
            'logout_redirect_route', 'logoutRedirectRoute' => $this->logoutRedirectRoute,
            'unauthorized_redirect_route', 'unauthorizedRedirectRoute' => $this->unauthorizedRedirectRoute,
            'session_lifetime', 'sessionLifetime' => $this->sessionLifetime,
            'secure_cookies', 'secureCookies' => $this->secureCookies,
            'http_client_options', 'httpClientOptions' => $this->httpClientOptions,
            'enabled' => $this->enabled,
            default => $default,
        };
    }

    /**
     * {@inheritDoc}
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
            'login_redirect_route' => $this->loginRedirectRoute,
            'logout_redirect_route' => $this->logoutRedirectRoute,
            'unauthorized_redirect_route' => $this->unauthorizedRedirectRoute,
            'session_lifetime' => $this->sessionLifetime,
            'secure_cookies' => $this->secureCookies,
            'http_client_options' => $this->httpClientOptions,
            'enabled' => $this->enabled,
        ];
    }

    public function getKeycloakUrl(): string
    {
        return $this->keycloakUrl;
    }

    public function getRealm(): string
    {
        return $this->realm;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function getProtectedRoutes(): array
    {
        return $this->protectedRoutes;
    }

    public function getCallbackRoute(): string
    {
        return $this->callbackRoute;
    }

    public function getLogoutRoute(): string
    {
        return $this->logoutRoute;
    }

    public function getLoginRedirectRoute(): string
    {
        return $this->loginRedirectRoute;
    }

    public function getLogoutRedirectRoute(): string
    {
        return $this->logoutRedirectRoute;
    }

    public function getUnauthorizedRedirectRoute(): string
    {
        return $this->unauthorizedRedirectRoute;
    }

    public function getSessionLifetime(): int
    {
        return $this->sessionLifetime;
    }

    public function getSecureCookies(): bool
    {
        return $this->secureCookies;
    }

    public function getHttpClientOptions(): array
    {
        return $this->httpClientOptions;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }
}
