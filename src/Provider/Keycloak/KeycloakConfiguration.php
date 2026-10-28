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

use Derafu\Array\ArrayReader;
use Derafu\Auth\Contract\KeycloakConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use Derafu\Value\ValueType;

/**
 * Configuration class for Keycloak authentication settings.
 */
class KeycloakConfiguration implements KeycloakConfigurationInterface
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
     * @var array<array-key, string>
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
     * @var array<array-key, mixed>
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
     * The audience that the access tokens of the clients of the API must have:
     * the identifier of the API in Keycloak. Empty: the client of the
     * application.
     */
    private string $apiAudience = '';

    /**
     * The client that asks Keycloak about the tokens of the API (introspection),
     * when the API is a client of its own. Empty: the client of the application.
     */
    private string $apiClientId = '';

    /**
     * The secret of the client of the API. Empty: the secret of the client of the
     * application.
     */
    private string $apiClientSecret = '';

    /**
     * Whether Keycloak is asked, for each request of a client of the API, if its
     * access token is still active.
     */
    private bool $apiIntrospection = true;

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
     * @throws TranslatableInvalidArgumentException If a configuration value has an invalid type.
     */
    public function __construct(array $config)
    {
        $reader = ArrayReader::fromArray($config);
        $this->keycloakUrl = $reader->getString('keycloak_url', $this->keycloakUrl);
        $this->realm = $reader->getString('realm', $this->realm);
        $this->clientId = $reader->getString('client_id', $this->clientId);
        $this->clientSecret = $reader->getString('client_secret', $this->clientSecret);
        $this->redirectUri = $reader->getString('redirect_uri', $this->redirectUri);

        $scopes = $reader->getArray('scopes') ?? $this->scopes;
        $scopeReader = ArrayReader::fromArray($scopes, 'Keycloak scopes');
        $this->scopes = [];
        foreach (array_keys($scopes) as $key) {
            $this->scopes[$key] = $scopeReader->require((string) $key, ValueType::string());
        }

        $this->callbackPath = $reader->getString('callback_path', $this->callbackPath);
        $this->httpClientOptions = array_filter(
            $reader->getArray('http_client_options') ?? [],
            fn (mixed $value) => $value !== null
        ) + $this->httpClientOptions;
        $this->issuer = $reader->getString('issuer', $this->issuer);
        $this->endSession = $reader->getBool('end_session', $this->endSession);
        $this->postLogoutRedirectUri = $reader->getString('post_logout_redirect_uri', $this->postLogoutRedirectUri);
        $this->apiAudience = trim($reader->getString('api_audience', $this->apiAudience));
        $this->apiIntrospection = $reader->getBool('api_introspection', $this->apiIntrospection);

        $this->apiClientId = trim($reader->getString('api_client_id', $this->apiClientId));
        $this->apiClientSecret = $reader->getString('api_client_secret', $this->apiClientSecret);
    }

    /**
     * {@inheritDoc}
     */
    public function validateWeb(): void
    {
        $this->validateRealm();

        if ($this->clientId === '') {
            throw new ConfigurationException('The client of Keycloak is not configured: set AUTH_KEYCLOAK_CLIENT_ID.');
        }

        if ($this->clientSecret === '') {
            throw new ConfigurationException('The secret of the client of Keycloak is not configured: set AUTH_KEYCLOAK_CLIENT_SECRET.');
        }

        if ($this->redirectUri === '') {
            throw new ConfigurationException('The redirect URI of Keycloak is not configured: set AUTH_KEYCLOAK_WEB_REDIRECT_URI.');
        }
        $this->validateAddress($this->redirectUri, 'AUTH_KEYCLOAK_WEB_REDIRECT_URI');
    }

    /**
     * {@inheritDoc}
     */
    public function validateApi(): void
    {
        $this->validateRealm();

        // The client of the API is both things or none: its secret is not the one
        // of the client of the application.
        if (($this->apiClientId === '') !== ($this->apiClientSecret === '')) {
            throw new ConfigurationException('The client of the API needs its ID and its secret, both: set AUTH_KEYCLOAK_API_CLIENT_ID and AUTH_KEYCLOAK_API_CLIENT_SECRET.');
        }

        if ($this->getApiAudience() === '') {
            throw new ConfigurationException('The audience of the API is not configured: set AUTH_KEYCLOAK_API_AUDIENCE, or the client with AUTH_KEYCLOAK_CLIENT_ID.');
        }

        if ($this->apiIntrospection) {
            if ($this->getApiClientId() === '' || $this->getApiClientSecret() === '') {
                throw new ConfigurationException('Keycloak is asked about the tokens with a client, and it is not configured: set AUTH_KEYCLOAK_CLIENT_ID and AUTH_KEYCLOAK_CLIENT_SECRET (or the ones of the API, AUTH_KEYCLOAK_API_CLIENT_ID and AUTH_KEYCLOAK_API_CLIENT_SECRET), or turn the introspection off with AUTH_KEYCLOAK_API_INTROSPECTION=false.');
            }

            // Keycloak answers about a token only to a client that is in its
            // audience (to any other it says that the token is not active, to the
            // client that asked for it too). The client that asks is the one of the
            // API, or the one of the application, so an audience that is another one
            // would close the API with no reason that shows.
            if ($this->apiAudience !== '' && $this->apiAudience !== $this->getApiClientId()) {
                throw new ConfigurationException([
                    'The audience of the API "{audience}" is not the client "{client}": Keycloak is asked about the tokens of the API by the client, and it only answers about the tokens that have it in their audience. Use the client as the audience, or turn the introspection off.',
                    'audience' => $this->apiAudience,
                    'client' => $this->getApiClientId(),
                ]);
            }
        }
    }

    /**
     * Checks the URL and the realm: what everything of Keycloak needs.
     */
    private function validateRealm(): void
    {
        if ($this->keycloakUrl === '') {
            throw new ConfigurationException('The URL of Keycloak is not configured: set AUTH_KEYCLOAK_URL.');
        }
        $this->validateAddress($this->keycloakUrl, 'AUTH_KEYCLOAK_URL');

        if ($this->realm === '') {
            throw new ConfigurationException('The realm of Keycloak is not configured: set AUTH_KEYCLOAK_REALM.');
        }
    }

    /**
     * Checks that a value is an absolute address (`http` or `https`): without a
     * scheme it would be a path of the site itself, and the user would be sent
     * to a page that does not exist.
     *
     * @throws ConfigurationException If it is not an absolute address.
     */
    private function validateAddress(string $value, string $variable): void
    {
        if (!preg_match('#^https?://[^/\s]+#i', $value)) {
            throw new ConfigurationException([
                'The value of {variable} "{value}" is not valid: it must be an address that starts with http:// or https://.',
                'variable' => $variable,
                'value' => $value,
            ]);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getKeycloakUrl(): string
    {
        return $this->keycloakUrl;
    }

    /**
     * {@inheritDoc}
     */
    public function getRealm(): string
    {
        return $this->realm;
    }

    /**
     * {@inheritDoc}
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * {@inheritDoc}
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * {@inheritDoc}
     */
    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    /**
     * {@inheritDoc}
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * {@inheritDoc}
     */
    public function getCallbackPath(): string
    {
        return $this->callbackPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getAccountUrl(): string
    {
        return $this->getRealmUrl() . '/account';
    }

    /**
     * {@inheritDoc}
     */
    public function getHttpClientOptions(): array
    {
        $options = $this->httpClientOptions;
        $options['headers'] = (array) ($options['headers'] ?? []);
        if (!isset(array_change_key_case($options['headers'], CASE_LOWER)['user-agent'])) {
            $options['headers']['User-Agent'] = $this->getUserAgent();
        }

        return $options;
    }

    /**
     * {@inheritDoc}
     */
    public function getUserAgent(): string
    {
        // A header has only printable ASCII: nothing of the configuration can break it.
        $client = preg_replace('/[^\x21-\x7E]/', '', $this->clientId);

        return $client !== null && $client !== '' ? sprintf('Derafu Auth (%s)', $client) : 'Derafu Auth';
    }

    /**
     * {@inheritDoc}
     */
    public function getIssuer(): string
    {
        return $this->issuer !== '' ? $this->issuer : $this->getRealmUrl();
    }

    /**
     * {@inheritDoc}
     */
    public function getRealmUrl(): string
    {
        return rtrim($this->keycloakUrl, '/') . '/realms/' . $this->realm;
    }

    /**
     * {@inheritDoc}
     */
    public function isEndSession(): bool
    {
        return $this->endSession;
    }

    /**
     * {@inheritDoc}
     */
    public function getPostLogoutRedirectUri(string $logoutRedirectPath = '/'): string
    {
        if ($this->postLogoutRedirectUri !== '') {
            return $this->postLogoutRedirectUri;
        }

        $route = $logoutRedirectPath;
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
    public function getApiAudience(): string
    {
        return $this->apiAudience !== '' ? $this->apiAudience : $this->getApiClientId();
    }

    /**
     * {@inheritDoc}
     */
    public function getApiClientId(): string
    {
        return $this->apiClientId !== '' ? $this->apiClientId : $this->clientId;
    }

    /**
     * {@inheritDoc}
     */
    public function getApiClientSecret(): string
    {
        return $this->apiClientSecret !== '' ? $this->apiClientSecret : $this->clientSecret;
    }

    /**
     * {@inheritDoc}
     */
    public function isApiIntrospection(): bool
    {
        return $this->apiIntrospection;
    }
}
