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

use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration class for Keycloak authentication settings.
 */
class KeycloakConfiguration
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
     */
    public function __construct(array $config)
    {
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
        $this->apiAudience = trim((string) ($config['api_audience'] ?? $this->apiAudience));
        $this->apiIntrospection = (bool) ($config['api_introspection'] ?? $this->apiIntrospection);

        $this->apiClientId = trim((string) ($config['api_client_id'] ?? $this->apiClientId));
        $this->apiClientSecret = (string) ($config['api_client_secret'] ?? $this->apiClientSecret);
    }

    /**
     * Checks what the web flow needs: the login of the user in Keycloak.
     *
     * It is checked when the flow is used, not when the configuration is made, so
     * a site that has it wrong fails where Keycloak is needed and not in every
     * page.
     *
     * @throws ConfigurationException If something that the login needs is not
     * configured, or is not a valid address.
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
            throw new ConfigurationException('The redirect URI of Keycloak is not configured: set AUTH_KEYCLOAK_REDIRECT_URI.');
        }
        $this->validateAddress($this->redirectUri, 'AUTH_KEYCLOAK_REDIRECT_URI');
    }

    /**
     * Checks what the API needs: to verify the tokens that Keycloak gave.
     *
     * Verifying a token needs the realm (its keys) and the audience. Asking
     * Keycloak whether the token is still active (the introspection) needs a
     * client that Keycloak accepts, and an audience that is that client.
     *
     * @throws ConfigurationException If something that the API needs is not
     * configured, or is not valid.
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
     * @param string $logoutRedirectPath The page of the site that follows the
     * logout (the one of the web channel), when no URL was configured.
     * @return string The URL: the one that was configured, or the page that
     * follows the logout in the site of the redirect URI.
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
     * Gets the audience that the access token of a client of the API must have
     * (the `aud` of the token): the identifier of the API in Keycloak.
     *
     * Without it, a token that Keycloak gave to any client of the realm, for any
     * other application, would be accepted by the API: the audience says that the
     * token was made to be used here. It is the client of the application unless
     * another one is configured. The roles of the client of the audience are the
     * ones of the client of the API (together with the ones of the realm).
     *
     * @return string The audience.
     */
    public function getApiAudience(): string
    {
        return $this->apiAudience !== '' ? $this->apiAudience : $this->getApiClientId();
    }

    /**
     * Gets the client that asks Keycloak about the tokens of the API
     * (introspection): the client of the API if it has one of its own, and the
     * client of the application otherwise.
     *
     * @return string The ID of the client.
     */
    public function getApiClientId(): string
    {
        return $this->apiClientId !== '' ? $this->apiClientId : $this->clientId;
    }

    /**
     * Gets the secret of the client that asks Keycloak about the tokens of the
     * API (see `getApiClientId()`).
     *
     * @return string The secret of the client.
     */
    public function getApiClientSecret(): string
    {
        return $this->apiClientSecret !== '' ? $this->apiClientSecret : $this->clientSecret;
    }

    /**
     * Gets whether Keycloak is asked, in each request of a client of the API,
     * whether its access token is still **active** (token introspection, RFC
     * 7662). It is, by default.
     *
     * A token is verified by what it says (its signature and its expiration), so a
     * token of a user that was disabled, or that was revoked, is valid until it
     * expires. Asking Keycloak closes that: the token that Keycloak does not
     * consider active is not valid, at once. It has a price, a request to Keycloak
     * for each request to the API. Turning it off is for the ones that give their
     * clients tokens that last a short time and trust that: the token is verified
     * with no request to Keycloak but the one for its keys, that are cached.
     *
     * Keycloak answers about a token only to a client that is in the audience of
     * the token, so with the introspection on the audience of the API is the
     * client that asks: the one of the API (`getApiClientId()`).
     *
     * @return bool True if the token is asked to Keycloak.
     */
    public function isApiIntrospection(): bool
    {
        return $this->apiIntrospection;
    }
}
