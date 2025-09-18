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
use Exception;
use GuzzleHttp\Client;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use Mezzio\Authentication\UserInterface;

/**
 * Keycloak user repository implementation.
 *
 * This repository handles user authentication through Keycloak
 * by validating tokens and retrieving user information.
 */
class KeycloakUserRepository implements UserRepositoryInterface
{
    private GenericProvider $provider;

    /**
     * Creates a new Keycloak user repository.
     *
     * @param KeycloakConfiguration $config The Keycloak configuration.
     */
    public function __construct(
        private readonly KeycloakConfiguration $config
    ) {
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

            return new KeycloakUser($userInfo);
        } catch (AuthenticationException) {
            return null;
        }
    }

    /**
     * Gets user information using an access token.
     *
     * @param string $accessToken The access token.
     * @return array<string, mixed> The user information.
     * @throws AuthenticationException If token validation fails.
     */
    public function getUserInfoFromToken(string $accessToken): array
    {
        try {
            $token = new AccessToken(['access_token' => $accessToken]);
            $user = $this->provider->getResourceOwner($token);
            $userInfo = $user->toArray();

            // Get the extra data from the JWT token payload, including roles.
            $tokenPayload = $this->parseJwtPayload($accessToken);
            $userInfo = array_merge($userInfo, $tokenPayload);

            return $userInfo;
        } catch (Exception $e) {
            throw new AuthenticationException(
                'Failed to get user info: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Exchanges an authorization code for an access token.
     *
     * @param string $code The authorization code.
     * @return array<string, mixed> The token information.
     * @throws AuthenticationException If code exchange fails.
     */
    public function exchangeCodeForToken(string $code): array
    {
        try {
            $token = $this->provider->getAccessToken('authorization_code', [
                'code' => $code,
            ]);

            return [
                'access_token' => $token->getToken(),
                'refresh_token' => $token->getRefreshToken(),
                'expires' => $token->getExpires(),
                'token_type' => $token->getValues()['token_type'] ?? 'Bearer',
            ];
        } catch (Exception $e) {
            throw new AuthenticationException(
                'Failed to exchange code for token: ' . $e->getMessage(),
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
                'expires' => $token->getExpires(),
                'token_type' => $token->getValues()['token_type'] ?? 'Bearer',
            ];
        } catch (Exception $e) {
            throw new AuthenticationException(
                'Failed to refresh token: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Creates an authorization URL for OAuth2 flow.
     *
     * @param array<string, mixed> $options Additional options for authorization URL.
     * @return string The authorization URL.
     */
    public function createAuthorizationUrl(array $options = []): string
    {
        return $this->provider->getAuthorizationUrl(array_merge([
            'scope' => implode(' ', $this->config->getScopes()),
        ], $options));
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

    /**
     * Parses the JWT token payload to extract roles and other claims.
     *
     * @param string $jwt The JWT token.
     * @return array<string, mixed> The parsed payload.
     * @throws AuthenticationException If JWT parsing fails.
     */
    private function parseJwtPayload(string $jwt): array
    {
        try {
            // Split JWT into parts (header.payload.signature)
            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                throw new AuthenticationException('Invalid JWT token format.');
            }

            // Decode the payload (second part)
            $payload = base64_decode(strtr($parts[1], '-_', '+/'));
            if (!$payload) {
                throw new AuthenticationException('Failed to decode JWT payload.');
            }

            $decoded = json_decode($payload, true);
            if ($decoded === null) {
                throw new AuthenticationException('Failed to parse JWT payload JSON.');
            }

            return $decoded;
        } catch (Exception $e) {
            throw new AuthenticationException(
                'Failed to parse JWT token: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }
}
