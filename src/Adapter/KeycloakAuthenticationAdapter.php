<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Adapter;

use Derafu\Auth\Contract\AuthConfigurationInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\User\KeycloakUser;
use Exception;
use GuzzleHttp\Client;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Mezzio\Authentication\AuthenticationInterface;
use Mezzio\Authentication\UserInterface;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Keycloak authentication adapter for Mezzio.
 *
 * This adapter implements Mezzio's AuthenticationInterface to provide
 * OAuth2/OpenID Connect authentication with Keycloak.
 */
class KeycloakAuthenticationAdapter implements AuthenticationInterface
{
    private GenericProvider $provider;

    private AuthConfigurationInterface $config;

    /**
     * Creates a new Keycloak authentication adapter.
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
    public function authenticate(ServerRequestInterface $request): ?UserInterface
    {
        $session = $request->getAttribute('session');
        if (!$session instanceof SessionInterface) {
            return null;
        }

        $path = $request->getUri()->getPath();

        // Handle logout.
        if ($this->isLogoutPath($path)) {
            $this->clearSession($session);
            return null;
        }

        // Handle authentication callback.
        if ($this->isCallbackPath($path)) {
            return $this->handleCallback($request, $session);
        }

        // Check if user is already authenticated.
        if ($this->hasAuthInfo($session)) {
            // Check if token has expired.
            if ($this->isTokenExpired($session)) {
                $refreshToken = $this->getRefreshToken($session);
                if ($refreshToken) {
                    try {
                        $tokenInfo = $this->refreshToken($refreshToken);
                        $this->storeAuthInfo($session, $tokenInfo);

                        // Get updated user info.
                        $userInfo = $this->getUserInfoFromToken(
                            $tokenInfo['access_token']
                        );
                        $this->storeUserInfo($session, $userInfo);

                        return new KeycloakUser($userInfo);
                    } catch (AuthenticationException $e) {
                        $this->clearSession($session);
                        return null;
                    }
                } else {
                    $this->clearSession($session);
                    return null;
                }
            }

            // Return existing user.
            $userInfo = $this->getUserInfo($session);
            if ($userInfo) {
                return new KeycloakUser($userInfo);
            }
        }

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function unauthorizedResponse(
        ServerRequestInterface $request
    ): ResponseInterface {
        $session = $request->getAttribute('session');
        if ($session instanceof SessionInterface) {
            // Store current URL for redirect after authentication.
            $this->storeRedirectUrl($session, (string) $request->getUri());

            // Generate authorization URL.
            $authUrl = $this->provider->getAuthorizationUrl();

            // Store state for CSRF protection.
            $state = $this->provider->getState();
            $this->storeState($session, $state);

            return new RedirectResponse($authUrl);
        }

        return new JsonResponse(['error' => 'Unauthorized'], 401);
    }

    /**
     * Handles the authentication callback.
     *
     * @param ServerRequestInterface $request The request.
     * @param SessionInterface $session The session.
     * @return UserInterface|null The authenticated user or null.
     */
    private function handleCallback(
        ServerRequestInterface $request,
        SessionInterface $session
    ): ?UserInterface {
        $queryParams = $request->getQueryParams();
        $savedState = $this->getState($session);

        // Verify state parameter for CSRF protection.
        if (!isset($queryParams['state']) || $savedState !== $queryParams['state']) {
            $this->clearState($session);
            return null;
        }

        // Process authorization code.
        if (!isset($queryParams['code'])) {
            return null;
        }

        try {
            // Exchange code for token.
            $tokenInfo = $this->exchangeCodeForToken($queryParams['code']);

            // Store authentication information.
            $this->storeAuthInfo($session, $tokenInfo);

            // Get and store user information.
            $userInfo = $this->getUserInfo($tokenInfo['access_token']);
            $this->storeUserInfo($session, $userInfo);

            // Clear state.
            $this->clearState($session);

            return new KeycloakUser($userInfo);

        } catch (AuthenticationException $e) {
            return null;
        }
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
     * Exchanges an authorization code for an access token.
     *
     * @param string $code The authorization code.
     * @return array The token information.
     * @throws AuthenticationException.
     */
    private function exchangeCodeForToken(string $code): array
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
     * Refreshes an access token using a refresh token.
     *
     * @param string $refreshToken The refresh token.
     * @return array The new token information.
     * @throws AuthenticationException.
     */
    private function refreshToken(string $refreshToken): array
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
     * Gets user information using an access token.
     *
     * @param string $accessToken The access token.
     * @return array The user information.
     * @throws AuthenticationException.
     */
    private function getUserInfoFromToken(string $accessToken): array
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

    /**
     * Checks if authentication information exists in the session.
     *
     * @param SessionInterface $session The session to check.
     * @return bool True if auth info exists, false otherwise.
     */
    private function hasAuthInfo(SessionInterface $session): bool
    {
        return $session->has('oauth2_token');
    }

    /**
     * Checks if the stored token has expired.
     *
     * @param SessionInterface $session The session to check.
     * @return bool True if token has expired, false otherwise.
     */
    private function isTokenExpired(SessionInterface $session): bool
    {
        return $session->has('oauth2_expiry') && $session->get('oauth2_expiry') < time();
    }

    /**
     * Gets the stored refresh token from the session.
     *
     * @param SessionInterface $session The session to get the token from.
     * @return string|null The refresh token or null if not found.
     */
    private function getRefreshToken(SessionInterface $session): ?string
    {
        return $session->get('oauth2_refresh_token');
    }

    /**
     * Stores authentication information in the session.
     *
     * @param SessionInterface $session The session to store the info in.
     * @param array $tokenInfo The token information to store.
     */
    private function storeAuthInfo(SessionInterface $session, array $tokenInfo): void
    {
        $session->set('oauth2_token', $tokenInfo['access_token']);
        if (isset($tokenInfo['refresh_token'])) {
            $session->set('oauth2_refresh_token', $tokenInfo['refresh_token']);
        }
        if (isset($tokenInfo['expires'])) {
            $session->set('oauth2_expiry', $tokenInfo['expires']);
        }
    }

    /**
     * Stores user information in the session.
     *
     * @param SessionInterface $session The session to store the info in.
     * @param array $userInfo The user information to store.
     */
    private function storeUserInfo(SessionInterface $session, array $userInfo): void
    {
        $session->set('user', $userInfo);
    }

    /**
     * Gets the stored user information from the session.
     *
     * @param SessionInterface $session The session to get the info from.
     * @return array|null The user information or null if not found.
     */
    private function getUserInfo(SessionInterface $session): ?array
    {
        return $session->get('user');
    }

    /**
     * Stores the state parameter for CSRF protection.
     *
     * @param SessionInterface $session The session to store the state in.
     * @param string $state The state parameter to store.
     */
    private function storeState(SessionInterface $session, string $state): void
    {
        $session->set('oauth2_state', $state);
    }

    /**
     * Gets the stored state parameter from the session.
     *
     * @param SessionInterface $session The session to get the state from.
     * @return string|null The state parameter or null if not found.
     */
    private function getState(SessionInterface $session): ?string
    {
        return $session->get('oauth2_state');
    }

    /**
     * Clears the stored state parameter from the session.
     *
     * @param SessionInterface $session The session to clear the state from.
     */
    private function clearState(SessionInterface $session): void
    {
        $session->unset('oauth2_state');
    }

    /**
     * Stores the redirect URL for after authentication.
     *
     * @param SessionInterface $session The session to store the URL in.
     * @param string $url The redirect URL to store.
     */
    private function storeRedirectUrl(SessionInterface $session, string $url): void
    {
        $session->set('auth_redirect', $url);
    }

    /**
     * Clears all authentication information from the session.
     *
     * @param SessionInterface $session The session to clear.
     */
    private function clearSession(SessionInterface $session): void
    {
        $session->unset('oauth2_token');
        $session->unset('oauth2_refresh_token');
        $session->unset('oauth2_expiry');
        $session->unset('user');
        $session->unset('oauth2_state');
        $session->unset('auth_redirect');
    }

    /**
     * Checks if a path is the authentication callback route.
     *
     * @param string $path The route path to check.
     * @return bool True if it's the callback route, false otherwise.
     */
    private function isCallbackPath(string $path): bool
    {
        return $path === $this->config->getCallbackRoute();
    }

    /**
     * Checks if a path is the logout route.
     *
     * @param string $path The route path to check.
     * @return bool True if it's the logout route, false otherwise.
     */
    private function isLogoutPath(string $path): bool
    {
        return $path === $this->config->getLogoutRoute();
    }
}
