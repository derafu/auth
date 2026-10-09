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

use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface as DerafuUserInterface;
use Derafu\Auth\Contract\UserRepositoryInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\UserFactory;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
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

    private ClientInterface $httpClient;

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
     * @param UserFactoryInterface|null $userFactory Makes the users.
     * @param ClientInterface|null $httpClient The client for the requests to
     * Keycloak. By default, one with the options of the configuration (the
     * timeouts, the verification of the certificate).
     */
    private readonly UserFactoryInterface $userFactory;

    public function __construct(
        private readonly KeycloakConfiguration $config,
        ?KeycloakTokenVerifier $verifier = null,
        ?UserFactoryInterface $userFactory = null,
        ?ClientInterface $httpClient = null
    ) {
        $this->userFactory = $userFactory ?? new UserFactory();
        $this->httpClient = $httpClient ?? new Client($this->config->getHttpClientOptions());

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

            return $this->createUser($userInfo);
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
            if ($this->isRejection($e)) {
                throw new AuthenticationException(['Failed to get user info: {error}', 'error' => $e->getMessage()], 0, $e);
            }

            throw new ProviderUnavailableException(['Failed to get user info: {error}', 'error' => $e->getMessage()], 0, $e);
        }

        if (($userInfo['sub'] ?? null) !== ($claims['sub'] ?? null)) {
            throw new AuthenticationException('The user of the user info is not the user of the token.');
        }

        return array_merge($userInfo, $claims);
    }

    /**
     * Verifies the access token that a client of the API sends: what the token
     * says (see `KeycloakTokenVerifier::verifyBearerToken()`) and, unless it is
     * turned off in the configuration, that Keycloak says that it is active (see
     * `introspect()`). The first is done before the second, so a token that is not
     * valid does not cost a request to Keycloak.
     *
     * @param string $accessToken The access token.
     * @return array<string, mixed> The claims of the token.
     * @throws AuthenticationException If the token is not valid, or it is not
     * active.
     * @throws ProviderUnavailableException If Keycloak can not be asked whether
     * the token is active: the token is not accepted without knowing.
     */
    public function verifyBearerToken(string $accessToken): array
    {
        $claims = $this->verifier->verifyBearerToken($accessToken, $this->config->getApiAudience());

        if ($this->config->isApiIntrospection()) {
            $this->introspect($accessToken, $claims);
        }

        return $claims;
    }

    /**
     * Asks Keycloak whether an access token is active (token introspection, RFC
     * 7662): it is not if it expired, if it was revoked, if the session that it
     * belongs to ended or if its user was disabled. The client of the application
     * authenticates with its credentials.
     *
     * @param string $accessToken The access token.
     * @param array<string, mixed> $claims What the token says.
     * @throws AuthenticationException If Keycloak says that the token is not
     * active, or that it is the token of another user.
     * @throws ProviderUnavailableException If Keycloak can not answer (it does not
     * answer, it fails, or it does not accept the credentials of the client): it
     * is not a token that is not valid.
     */
    private function introspect(string $accessToken, array $claims): void
    {
        try {
            $response = $this->httpClient->request('POST', $this->getIntrospectionUrl(), [
                'form_params' => [
                    'token' => $accessToken,
                    'token_type_hint' => 'access_token',
                    'client_id' => $this->config->getApiClientId(),
                    'client_secret' => $this->config->getApiClientSecret(),
                ],
                'headers' => ['Accept' => 'application/json'],
                'http_errors' => false,
            ]);
            $status = $response->getStatusCode();
            $answer = json_decode((string) $response->getBody(), true);
        } catch (Exception $e) {
            throw new ProviderUnavailableException(['Failed to introspect the token: {error}', 'error' => $e->getMessage()], 0, $e);
        }

        // Anything but an answer is Keycloak that can not say it.
        if ($status !== 200 || !is_array($answer)) {
            throw new ProviderUnavailableException([
                'Failed to introspect the token: {error}',
                'error' => 'HTTP status ' . $status,
            ]);
        }

        if (($answer['active'] ?? false) !== true) {
            throw new AuthenticationException('The token is not active.');
        }

        if (isset($answer['sub']) && $answer['sub'] !== ($claims['sub'] ?? null)) {
            throw new AuthenticationException('The user of the introspection is not the user of the token.');
        }
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
            if ($this->isRejection($e)) {
                throw new AuthenticationException(['Failed to refresh token: {error}', 'error' => $e->getMessage()], 0, $e);
            }

            throw new ProviderUnavailableException(['Failed to refresh token: {error}', 'error' => $e->getMessage()], 0, $e);
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
     * @param string $logoutRedirectPath The page of the site that follows the
     * logout, if the configuration has no post logout redirect URI.
     * @return string The URL, which sends the user back to the post logout
     * redirect URI of the configuration.
     */
    public function getLogoutUrl(?string $idToken = null, string $logoutRedirectPath = '/'): string
    {
        return $this->config->getRealmUrl() . '/protocol/openid-connect/logout?' . http_build_query(array_filter([
            'client_id' => $this->config->getClientId(),
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $this->config->getPostLogoutRedirectUri($logoutRedirectPath),
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
     * Makes the user from what Keycloak says about it (the claims of the access
     * token and the user info).
     *
     * The identity is the `sub`, the roles are the ones of the realm and the ones
     * of the client of the application, and the details are the claims as they
     * are: the standard fields of the user (name, email...) are the claims of
     * OpenID Connect, and the claims that a mapper of the realm adds (an
     * attribute of the user, its groups) are there too. A claim that is not there
     * is a field that is `null`, not an error. The user is made by the factory,
     * so it is the class of user of the application.
     *
     * @param array<string, mixed> $userInfo The claims and the user info.
     * @param string|null $client The client whose roles are the ones of the user
     * (together with the ones of the realm): the one of the application by
     * default, and the one of the audience for a client of the API.
     * @return DerafuUserInterface The user.
     * @throws AuthenticationException If there is no `sub`.
     */
    public function createUser(array $userInfo, ?string $client = null): DerafuUserInterface
    {
        $identity = $userInfo['sub']
            ?? throw new AuthenticationException('User identity not found in keycloak user info.');

        return $this->userFactory->create(
            (string) $identity,
            $this->extractRoles($userInfo, $client ?? $this->config->getClientId()),
            $userInfo
        );
    }

    /**
     * The roles of the user: the ones of the realm and the ones of the client of
     * the application (what the user can do in another client says nothing about
     * this one), as texts and without duplicates.
     *
     * @param array<string, mixed> $userInfo
     * @param string $clientId The client whose roles count.
     * @return list<string>
     */
    private function extractRoles(array $userInfo, string $clientId): array
    {
        $roles = is_array($userInfo['roles'] ?? null) ? $userInfo['roles'] : [];

        $realmAccess = $userInfo['realm_access'] ?? [];
        if (is_array($realmAccess) && is_array($realmAccess['roles'] ?? null)) {
            $roles = array_merge($roles, $realmAccess['roles']);
        }

        $resourceAccess = $userInfo['resource_access'] ?? [];
        $access = is_array($resourceAccess) ? ($resourceAccess[$clientId] ?? null) : null;
        if (is_array($access) && is_array($access['roles'] ?? null)) {
            $roles = array_merge($roles, $access['roles']);
        }

        return array_values(array_unique(array_filter($roles, 'is_string')));
    }

    /**
     * Tells whether a failure of a request that asks Keycloak about a session is
     * Keycloak saying that the session is over.
     *
     * Keycloak saying that the refresh token or the access token is not valid
     * (`invalid_grant`, `invalid_token`) is a rejection. Anything else (it does
     * not answer, it is down or it fails, it does not know the application) says
     * nothing about the session.
     *
     * @param Exception $e What failed.
     */
    private function isRejection(Exception $e): bool
    {
        $body = $e instanceof IdentityProviderException ? $e->getResponseBody() : null;
        $error = is_array($body) ? ($body['error'] ?? null) : null;

        return in_array($error, ['invalid_grant', 'invalid_token'], true);
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
        $this->provider = new GenericProvider([
            'clientId' => $this->config->getClientId(),
            'clientSecret' => $this->config->getClientSecret(),
            'redirectUri' => $this->config->getRedirectUri(),
            'urlAuthorize' => $this->getAuthorizationUrl(),
            'urlAccessToken' => $this->getTokenUrl(),
            'urlResourceOwnerDetails' => $this->getUserInfoUrl(),
            'scopes' => $this->config->getScopes(),
            'pkceMethod' => GenericProvider::PKCE_METHOD_S256,
        ], [
            // A collaborator, not an option: the provider takes the client from
            // here, and makes one of its own (without the timeouts and the
            // verification of the configuration) if it is not.
            'httpClient' => $this->httpClient,
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
    private function getIntrospectionUrl(): string
    {
        return $this->config->getRealmUrl() . '/protocol/openid-connect/token/introspect';
    }

    /**
     * Gets the URL of the user info.
     *
     * @return string The URL.
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
