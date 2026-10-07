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
     * The Keycloak callback path.
     *
     * @var string
     */
    private string $callbackPath = '/auth/callback';

    /**
     * The Keycloak HTTP client options.
     *
     * @var array
     */
    private array $httpClientOptions = [
        'timeout' => 30,
        'connect_timeout' => 30,
        'verify' => true,
    ];

    /**
     * The issuer of the tokens: the URL of the realm as the clients of Keycloak
     * see it (the `iss` of its tokens). It is the URL of the realm unless
     * Keycloak is reached by another URL than the one it publishes.
     *
     * @var string
     */
    private string $issuer = '';

    /**
     * Whether the logout also ends the session of the user in Keycloak.
     *
     * @var bool
     */
    private bool $endSession = true;

    /**
     * The URL where Keycloak sends the user after the logout. It must be one of
     * the post logout redirect URIs of the client. If it is empty it is the page
     * that follows the logout, in the site of the redirect URI.
     *
     * @var string
     */
    private string $postLogoutRedirectUri = '';

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
        $this->callbackPath = $config['callback_path']
            ?? $this->callbackPath
        ;
        $this->httpClientOptions = array_filter(
            $config['http_client_options'] ?? [],
            fn (mixed $value) => $value !== null
        ) + $this->httpClientOptions;
        $this->issuer = $config['issuer']
            ?? $this->issuer
        ;
        $this->endSession = $config['end_session']
            ?? $this->endSession
        ;
        $this->postLogoutRedirectUri = $config['post_logout_redirect_uri']
            ?? $this->postLogoutRedirectUri
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
            'callback_path' => $this->getCallbackPath(),
            'http_client_options' => $this->getHttpClientOptions(),
            'issuer' => $this->getIssuer(),
            'end_session' => $this->isEndSession(),
            'post_logout_redirect_uri' => $this->getPostLogoutRedirectUri(),
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
            'callback_path' => $this->getCallbackPath(),
            'http_client_options' => $this->getHttpClientOptions(),
            'issuer' => $this->getIssuer(),
            'end_session' => $this->isEndSession(),
            'post_logout_redirect_uri' => $this->getPostLogoutRedirectUri(),
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
     * Gets the Keycloak callback path.
     *
     * @return string The Keycloak callback path.
     */
    public function getCallbackPath(): string
    {
        return $this->callbackPath;
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
     * Gets the issuer of the tokens (their `iss`).
     *
     * @return string The URL of the realm, or the issuer that was configured.
     */
    public function getIssuer(): string
    {
        return $this->issuer !== '' ? $this->issuer : $this->getRealmUrl();
    }

    /**
     * Gets the URL of the realm, where the endpoints of Keycloak are.
     *
     * @return string The URL of the realm.
     */
    public function getRealmUrl(): string
    {
        return rtrim($this->keycloakUrl, '/') . '/realms/' . $this->realm;
    }

    /**
     * Whether the logout also ends the session of the user in Keycloak.
     *
     * @return bool True if it does.
     */
    public function isEndSession(): bool
    {
        return $this->endSession;
    }

    /**
     * Gets the URL where Keycloak sends the user after the logout.
     *
     * @return string The URL: the one that was configured, or the page that
     * follows the logout in the site of the redirect URI.
     */
    public function getPostLogoutRedirectUri(): string
    {
        if ($this->postLogoutRedirectUri !== '') {
            return $this->postLogoutRedirectUri;
        }

        $route = $this->getLogoutRedirectPath();
        if (preg_match('#^https?://#', $route)) {
            return $route;
        }

        $uri = parse_url($this->redirectUri);
        $origin = ($uri['scheme'] ?? 'https') . '://' . ($uri['host'] ?? '')
            . (isset($uri['port']) ? ':' . $uri['port'] : '');

        return $origin . '/' . ltrim($route, '/');
    }

    /**
     * {@inheritDoc}
     */
    public function getLoginPath(): string
    {
        return $this->getCallbackPath();
    }
}
