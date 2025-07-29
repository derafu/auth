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

use Derafu\Auth\Contract\AuthConfigurableInterface;
use Derafu\Auth\Contract\AuthConfigurationInterface;
use Derafu\Auth\Contract\AuthenticationProviderInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Exception;
use GuzzleHttp\Client;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * Keycloak authentication service implementation.
 *
 * This service handles OAuth2 authentication with Keycloak using the League
 * OAuth2 Client library.
 */
class KeycloakAuthenticationService implements AuthenticationProviderInterface, AuthConfigurableInterface
{
    private GenericProvider $provider;

    private AuthConfigurationInterface $config;

    /**
     * Creates a new Keycloak authentication service.
     *
     * @param AuthConfigurationInterface $config The configuration object.
     */
    public function __construct(AuthConfigurationInterface $config)
    {
        $this->config = $config;
        $this->initializeProvider();
    }

    /**
     * {@inheritDoc}
     */
    public function createAuthorizationUrl(array $options = []): string
    {
        return $this->provider->getAuthorizationUrl(array_merge([
            'scope' => implode(' ', $this->config->getScopes()),
        ], $options));
    }

    /**
     * {@inheritDoc}
     */
    public function getState(): string
    {
        return $this->provider->getState();
    }

    /**
     * {@inheritDoc}
     */
    public function exchangeCodeForToken(string $code): array
    {
        try {
            $token = $this->provider->getAccessToken('authorization_code', [
                'code' => $code,
            ]);

            return $this->tokenToArray($token);
        } catch (Exception $e) {
            throw new AuthenticationException(
                'Failed to exchange code for token: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function refreshToken(string $refreshToken): array
    {
        try {
            $token = $this->provider->getAccessToken('refresh_token', [
                'refresh_token' => $refreshToken,
            ]);

            return $this->tokenToArray($token);
        } catch (Exception $e) {
            throw new AuthenticationException(
                'Failed to refresh token: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getUserInfo(string $accessToken): array
    {
        try {
            $token = new AccessToken(['access_token' => $accessToken]);
            $user = $this->provider->getResourceOwner($token);

            return $user->toArray();
        } catch (Exception $e) {
            throw new AuthenticationException(
                'Failed to get user info: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function isTokenValid(string $accessToken): bool
    {
        try {
            $token = new AccessToken(['access_token' => $accessToken]);
            $this->provider->getResourceOwner($token);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function setConfiguration(array $configuration): static
    {
        $this->config = new \Derafu\Auth\Configuration\AuthConfiguration($configuration);
        $this->initializeProvider();

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getConfiguration(): AuthConfigurationInterface
    {
        return $this->config;
    }

    /**
     * {@inheritDoc}
     */
    public function resolveConfiguration(array $configuration): AuthConfigurationInterface
    {
        return new \Derafu\Auth\Configuration\AuthConfiguration($configuration);
    }

    /**
     * {@inheritDoc}
     */
    public function getConfigurationSchema(): array
    {
        return [
            'keycloak_url' => [
                'type' => 'string',
                'required' => true,
            ],
            'realm' => [
                'type' => 'string',
                'required' => false,
                'default' => 'master',
            ],
            'client_id' => [
                'type' => 'string',
                'required' => true,
            ],
            'client_secret' => [
                'type' => 'string',
                'required' => true,
            ],
            'redirect_uri' => [
                'type' => 'string',
                'required' => true,
            ],
            'scopes' => [
                'type' => 'array',
                'required' => false,
                'default' => ['openid'],
            ],
            'protected_routes' => [
                'type' => 'array',
                'required' => false,
                'default' => ['/dashboard', '/profile', '/admin'],
            ],
            'callback_route' => [
                'type' => 'string',
                'required' => false,
                'default' => '/auth/callback',
            ],
            'logout_route' => [
                'type' => 'string',
                'required' => false,
                'default' => '/auth/logout',
            ],
            'session_lifetime' => [
                'type' => 'integer',
                'required' => false,
                'default' => 3600,
            ],
            'secure_cookies' => [
                'type' => 'boolean',
                'required' => false,
                'default' => false,
            ],
            'http_client_options' => [
                'type' => 'array',
                'required' => false,
                'default' => [],
            ],
        ];
    }

    /**
     * Initializes the OAuth2 provider.
     *
     * @return void
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
     * Converts a token to an array.
     *
     * @param AccessTokenInterface $token The token.
     * @return array The token as array.
     */
    private function tokenToArray(AccessTokenInterface $token): array
    {
        return [
            'access_token' => $token->getToken(),
            'refresh_token' => $token->getRefreshToken(),
            'expires' => $token->getExpires(),
            'token_type' => $token->getValues()['token_type'] ?? 'Bearer',
        ];
    }
}
