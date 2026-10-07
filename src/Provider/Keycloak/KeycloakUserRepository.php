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

use Derafu\Auth\Contract\UserRepositoryInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ConfigurationException;
use Exception;
use GuzzleHttp\Client;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use Mezzio\Authentication\UserInterface;

/**
 * Keycloak user repository implementation.
 *
 * This repository is the protocol with Keycloak (OpenID Connect, authorization
 * code flow with PKCE): the authorization URL, the exchange of the code, the
 * refresh of the tokens, the verification of the tokens that Keycloak gives
 * (their signature, issuer, expiration, audience and nonce), and the user
 * information.
 */
class KeycloakUserRepository implements UserRepositoryInterface
{
    private GenericProvider $provider;

    private KeycloakTokenVerifier $verifier;

    /**
     * The nonce of the authorization URL that was created last.
     */
    private string $nonce = '';

    /**
     * Creates a new Keycloak user repository.
     *
     * @param KeycloakConfiguration $config The Keycloak configuration.
     * @param KeycloakTokenVerifier|null $verifier Verifies the tokens. By
     * default, one that reads the keys of the realm of the configuration.
     */
    public function __construct(
        private readonly KeycloakConfiguration $config,
        ?KeycloakTokenVerifier $verifier = null
    ) {
        if (!class_exists(GenericProvider::class)) {
            throw new ConfigurationException(
                'The Keycloak provider requires "league/oauth2-client". Run: composer require league/oauth2-client'
            );
        }

        $this->verifier = $verifier ?? new KeycloakTokenVerifier($config);
        $this->initializeProvider();
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(string $credential, ?string $password = null): ?UserInterface
    {
        try {
            // For Keycloak, credential is the access token.
            $userInfo = $this->getUserInfoFromToken($credential);

            return new KeycloakUser($userInfo, $this->config->getClientId());
        } catch (AuthenticationException) {
            return null;
        }
    }

    /**
     * Gets user information using an access token.
     *
     * The token is verified (its signature, issuer, expiration and that it was
     * given to this client), and the user information of Keycloak must be the one
     * of the user of the token. The claims of the token (the roles, for example)
     * are added to the user information.
     *
     * @param string $accessToken The access token.
     * @return array<string, mixed> The user information.
     * @throws AuthenticationException If token validation fails.
     */
    public function getUserInfoFromToken(string $accessToken): array
    {
        $claims = $this->verifier->verifyAccessToken($accessToken);

        try {
            $user = $this->provider->getResourceOwner(new AccessToken(['access_token' => $accessToken]));
            $userInfo = $user->toArray();
        } catch (Exception $e) {
            throw new AuthenticationException(
                ['Failed to get user info: {error}', 'error' => $e->getMessage()],
                0,
                $e
            );
        }

        if (($userInfo['sub'] ?? null) !== ($claims['sub'] ?? null)) {
            throw new AuthenticationException('The user of the user info is not the user of the token.');
        }

        return array_merge($userInfo, $claims);
    }

    /**
     * Exchanges an authorization code for an access token.
     *
     * @param string $code The authorization code.
     * @param string|null $pkceCode The PKCE code (the verifier) of the login.
     * @return array<string, mixed> The token information.
     * @throws AuthenticationException If code exchange fails.
     */
    public function exchangeCodeForToken(string $code, ?string $pkceCode = null): array
    {
        try {
            // Always set: a code that this repository made for another login must
            // not go with this one.
            $this->provider->setPkceCode($pkceCode);

            $token = $this->provider->getAccessToken('authorization_code', [
                'code' => $code,
            ]);

            return [
                'access_token' => $token->getToken(),
                'refresh_token' => $token->getRefreshToken(),
                'id_token' => $token->getValues()['id_token'] ?? null,
                'expires' => $token->getExpires(),
                'token_type' => $token->getValues()['token_type'] ?? 'Bearer',
            ];
        } catch (Exception $e) {
            throw new AuthenticationException(
                ['Failed to exchange code for token: {error}', 'error' => $e->getMessage()],
                0,
                $e
            );
        }
    }

    /**
     * Refreshes an access token using a refresh token.
     *
     * @param string $refreshToken The refresh token.
     * @return array<string, mixed> The new token information.
     * @throws AuthenticationException If token refresh fails.
     */
    public function refreshToken(string $refreshToken): array
    {
        try {
            $token = $this->provider->getAccessToken('refresh_token', [
                'refresh_token' => $refreshToken,
            ]);

            return [
                'access_token' => $token->getToken(),
                'refresh_token' => $token->getRefreshToken(),
                'id_token' => $token->getValues()['id_token'] ?? null,
                'expires' => $token->getExpires(),
                'token_type' => $token->getValues()['token_type'] ?? 'Bearer',
            ];
        } catch (Exception $e) {
            throw new AuthenticationException(
                ['Failed to refresh token: {error}', 'error' => $e->getMessage()],
                0,
                $e
            );
        }
    }

    /**
     * Creates an authorization URL for OAuth2 flow.
     *
     * It has the `state` (against CSRF), the `nonce` (that the ID token must
     * have) and the PKCE challenge. What the login needs to finish is read after
     * this: `getState()`, `getNonce()` and `getPkceCode()`.
     *
     * @param array<string, mixed> $options Additional options for authorization URL.
     * @return string The authorization URL.
     */
    public function createAuthorizationUrl(array $options = []): string
    {
        $this->nonce = bin2hex(random_bytes(16));

        return $this->provider->getAuthorizationUrl(array_merge([
            'scope' => implode(' ', $this->config->getScopes()),
            'nonce' => $this->nonce,
        ], $options));
    }

    /**
     * Gets the nonce of the authorization URL that was created last.
     *
     * @return string The nonce.
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * Gets the PKCE code (the verifier) of the authorization URL that was
     * created last.
     *
     * @return string|null The PKCE code.
     */
    public function getPkceCode(): ?string
    {
        return $this->provider->getPkceCode();
    }

    /**
     * Verifies the ID token of a login.
     *
     * @param string $idToken The ID token.
     * @param string $nonce The nonce of the authorization URL of the login.
     * @return array<string, mixed> The claims of the ID token.
     * @throws AuthenticationException If the ID token is not valid.
     */
    public function verifyIdToken(string $idToken, string $nonce): array
    {
        return $this->verifier->verifyIdToken($idToken, $nonce);
    }

    /**
     * Gets the URL that ends the session of the user in Keycloak.
     *
     * @param string|null $idToken The ID token of the session, that tells
     * Keycloak which session it is.
     * @return string The URL, which sends the user back to the post logout
     * redirect URI of the configuration.
     */
    public function getLogoutUrl(?string $idToken = null): string
    {
        return $this->config->getRealmUrl() . '/protocol/openid-connect/logout?' . http_build_query(array_filter([
            'client_id' => $this->config->getClientId(),
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $this->config->getPostLogoutRedirectUri(),
        ]));
    }

    /**
     * Gets the state parameter for CSRF protection.
     *
     * @return string The state parameter.
     */
    public function getState(): string
    {
        return $this->provider->getState();
    }

    /**
     * Validates if an access token is still valid.
     *
     * @param string $accessToken The access token to validate.
     * @return bool True if token is valid, false otherwise.
     */
    public function isTokenValid(string $accessToken): bool
    {
        try {
            $this->getUserInfoFromToken($accessToken);
            return true;
        } catch (AuthenticationException) {
            return false;
        }
    }

    /**
     * Gets the OAuth2 provider instance.
     *
     * @return GenericProvider The OAuth2 provider.
     */
    public function getProvider(): GenericProvider
    {
        return $this->provider;
    }

    /**
     * Initializes the OAuth2 provider.
     */
    private function initializeProvider(): void
    {
        $httpClient = new Client($this->config->getHttpClientOptions());

        $this->provider = new GenericProvider([
            'clientId' => $this->config->getClientId(),
            'clientSecret' => $this->config->getClientSecret(),
            'redirectUri' => $this->config->getRedirectUri(),
            'urlAuthorize' => $this->getAuthorizationUrl(),
            'urlAccessToken' => $this->getTokenUrl(),
            'urlResourceOwnerDetails' => $this->getUserInfoUrl(),
            'scopes' => $this->config->getScopes(),
            'httpClient' => $httpClient,
            'pkceMethod' => GenericProvider::PKCE_METHOD_S256,
        ]);
    }

    /**
     * Gets the authorization URL.
     *
     * @return string The authorization URL.
     */
    private function getAuthorizationUrl(): string
    {
        return
            $this->config->getKeycloakUrl()
            . '/realms/'
            . $this->config->getRealm()
            . '/protocol/openid-connect/auth'
        ;
    }

    /**
     * Gets the token URL.
     *
     * @return string The token URL.
     */
    private function getTokenUrl(): string
    {
        return
            $this->config->getKeycloakUrl()
            . '/realms/'
            . $this->config->getRealm()
            . '/protocol/openid-connect/token'
        ;
    }

    /**
     * Gets the user info URL.
     *
     * @return string The user info URL.
     */
    private function getUserInfoUrl(): string
    {
        return
            $this->config->getKeycloakUrl()
            . '/realms/'
            . $this->config->getRealm()
            . '/protocol/openid-connect/userinfo'
        ;
    }
}
