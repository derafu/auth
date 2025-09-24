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

use Derafu\Auth\Abstract\AbstractProviderConfiguration;
use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration class for Keycloak authentication settings.
 */
class KeycloakConfiguration extends AbstractProviderConfiguration implements ConfigurationInterface
{
    /**
     * The Keycloak URL.
     *
     * @var string
     */
    private string $keycloakUrl = '';

    /**
     * The Keycloak realm.
     *
     * @var string
     */
    private string $realm = 'master';

    /**
     * The Keycloak client ID.
     *
     * @var string
     */
    private string $clientId = '';

    /**
     * The Keycloak client secret.
     *
     * @var string
     */
    private string $clientSecret = '';

    /**
     * The Keycloak redirect URI.
     *
     * @var string
     */
    private string $redirectUri = '';

    /**
     * The Keycloak scopes.
     *
     * @var array
     */
    private array $scopes = ['openid', 'profile', 'email'];

    /**
     * The Keycloak callback route.
     *
     * @var string
     */
    private string $callbackRoute = '/auth/callback';

    /**
     * The Keycloak HTTP client options.
     *
     * @var array
     */
    private array $httpClientOptions = [
        'timeout' => 30,
        'connect_timeout' => 30,
        'verify' => false,
    ];

    /**
     * Creates a new Keycloak configuration.
     *
     * @param array<string, mixed> $config The configuration array.
     */
    public function __construct(array $config)
    {
        parent::__construct($config);

        $this->keycloakUrl = $config['keycloak_url']
            ?? $this->keycloakUrl
        ;
        $this->realm = $config['realm']
            ?? $this->realm
        ;
        $this->clientId = $config['client_id']
            ?? $this->clientId
        ;
        $this->clientSecret = $config['client_secret']
            ?? $this->clientSecret
        ;
        $this->redirectUri = $config['redirect_uri']
            ?? $this->redirectUri
        ;
        $this->scopes = $config['scopes']
            ?? $this->scopes
        ;
        $this->callbackRoute = $config['callback_route']
            ?? $this->callbackRoute
        ;
        $this->httpClientOptions = $config['http_client_options']
            ?? $this->httpClientOptions
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
        $value = parent::get($key, $default);
        if ($value !== null) {
            return $value;
        }

        return match ($key) {
            'keycloak_url' => $this->getKeycloakUrl(),
            'realm' => $this->getRealm(),
            'client_id' => $this->getClientId(),
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->getRedirectUri(),
            'scopes' => $this->getScopes(),
            'callback_route' => $this->getCallbackRoute(),
            'http_client_options' => $this->getHttpClientOptions(),
            default => $default,
        };
    }

    /**
     * {@inheritDoc}
     */
    public function toArray(): array
    {
        $array = parent::toArray();

        return array_merge($array, [
            'keycloak_url' => $this->getKeycloakUrl(),
            'realm' => $this->getRealm(),
            'client_id' => $this->getClientId(),
            'client_secret' => $this->getClientSecret(),
            'redirect_uri' => $this->getRedirectUri(),
            'scopes' => $this->getScopes(),
            'callback_route' => $this->getCallbackRoute(),
            'http_client_options' => $this->getHttpClientOptions(),
        ]);
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
     * Gets the Keycloak client ID.
     *
     * @return string The Keycloak client ID.
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * Gets the Keycloak client secret.
     *
     * @return string The Keycloak client secret.
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * Gets the Keycloak redirect URI.
     *
     * @return string The Keycloak redirect URI.
     */
    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    /**
     * Gets the Keycloak scopes.
     *
     * @return array The Keycloak scopes.
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * Gets the Keycloak callback route.
     *
     * @return string The Keycloak callback route.
     */
    public function getCallbackRoute(): string
    {
        return $this->callbackRoute;
    }

    /**
     * Gets the Keycloak HTTP client options.
     *
     * @return array The Keycloak HTTP client options.
     */
    public function getHttpClientOptions(): array
    {
        return $this->httpClientOptions;
    }

    /**
     * {@inheritDoc}
     */
    public function getLoginPath(): string
    {
        return $this->getCallbackRoute();
    }
}
