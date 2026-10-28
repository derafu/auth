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
use Derafu\Auth\Contract\KeycloakTokenVerifierInterface;
use Derafu\Auth\Contract\KeycloakUserRepositoryInterface;
use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface as DerafuUserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\UserFactory;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
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
class KeycloakUserRepository implements KeycloakUserRepositoryInterface
{
    private GenericProvider $provider;

    private KeycloakTokenVerifierInterface $verifier;

    private ClientInterface $httpClient;

    /**
     * The nonce of the authorization URL that was created last.
     */
    private string $nonce = '';

    /**
     * Creates a new Keycloak user repository.
     *
     * @param KeycloakConfigurationInterface $config The Keycloak configuration.
     * @param KeycloakTokenVerifierInterface|null $verifier Verifies the tokens. By
     * default, one that reads the keys of the realm of the configuration.
     * @param UserFactoryInterface|null $userFactory Makes the users.
     * @param ClientInterface|null $httpClient The client for the requests to
     * Keycloak. By default, one with the options of the configuration (the
     * timeouts, the verification of the certificate).
     */
    private readonly UserFactoryInterface $userFactory;

    public function __construct(
        private readonly KeycloakConfigurationInterface $config,
        ?KeycloakTokenVerifierInterface $verifier = null,
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
     * {@inheritDoc}
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    public function exchangeCodeForToken(string $code, ?string $pkceCode = null): array
    {
        try {
            // Always set: a code that this repository made for another login must
            // not go with this one.
            $this->provider->setPkceCode($pkceCode ?? '');

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
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    public function requestOfflineToken(string $username, string $password, ?string $otp = null): array
    {
        try {
            $response = $this->httpClient->request('POST', $this->config->getRealmUrl() . '/protocol/openid-connect/token', [
                'form_params' => array_filter([
                    'grant_type' => 'password',
                    'client_id' => $this->config->getClientId(),
                    'client_secret' => $this->config->getClientSecret(),
                    'username' => $username,
                    'password' => $password,
                    'totp' => $otp,
                    'scope' => 'openid offline_access',
                ], fn ($value) => $value !== null && $value !== ''),
                'headers' => ['Accept' => 'application/json'],
                'http_errors' => false,
            ]);
            $status = $response->getStatusCode();
            $answer = json_decode((string) $response->getBody(), true);
        } catch (Exception $e) {
            throw new ProviderUnavailableException(['Failed to ask Keycloak for a token: {error}', 'error' => $e->getMessage()], 0, $e);
        }

        if ($status >= 500 || !is_array($answer)) {
            throw new ProviderUnavailableException(['Failed to ask Keycloak for a token: {error}', 'error' => 'HTTP status ' . $status]);
        }

        if ($status !== 200) {
            // The client has no direct access grants: it is the configuration of the
            // application, not a mistake of the user.
            if (in_array($answer['error'] ?? '', ['unauthorized_client', 'invalid_client'], true)) {
                throw new AuthenticationException(
                    'Keycloak does not let this application make tokens with a password: turn on the direct access grants of its client.',
                    400
                );
            }

            // What is wrong with the user, when Keycloak says it. For a password that is
            // not valid, a code of the second factor that is not valid and one that is
            // missing it says the same, so the caller works out which is more likely.
            try {
                $description = ArrayReader::fromArray($answer, 'Keycloak token response')->getString('error_description', '');
            } catch (TranslatableInvalidArgumentException $e) {
                throw new AuthenticationException(
                    ['Invalid response from Keycloak: {error}', 'error' => $e->getMessage()],
                    400,
                    $e
                );
            }
            if ($description === 'Account disabled') {
                throw new AuthenticationException('Your user is disabled.', 403);
            }
            if ($description === 'Account is not fully set up') {
                throw new AuthenticationException(
                    'Your user has actions pending in Keycloak (a password to change, an email to verify...): complete them and try again.',
                    403
                );
            }

            throw new AuthenticationException('The password is not valid.', 401);
        }

        $token = $answer['refresh_token'] ?? null;
        if (!is_string($token) || !TokenClaims::isOffline($token)) {
            throw new AuthenticationException('The token that Keycloak gave is not one for the API.', 400);
        }

        $answer['refresh_token'] = $token;

        return $answer;
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * {@inheritDoc}
     */
    public function getPkceCode(): ?string
    {
        $code = $this->provider->getPkceCode();

        return $code === '' ? null : $code;
    }

    /**
     * {@inheritDoc}
     */
    public function verifyIdToken(string $idToken, string $nonce): array
    {
        return $this->verifier->verifyIdToken($idToken, $nonce);
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    public function getState(): string
    {
        return $this->provider->getState();
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    public function createUser(array $userInfo, ?string $client = null): DerafuUserInterface
    {
        if (!isset($userInfo['sub'])) {
            throw new AuthenticationException('User identity not found in keycloak user info.');
        }

        try {
            $identity = ArrayReader::fromArray($userInfo, 'Keycloak user info')->requireString('sub');
        } catch (TranslatableInvalidArgumentException $e) {
            throw new AuthenticationException(
                ['Invalid response from Keycloak: {error}', 'error' => $e->getMessage()],
                400,
                $e
            );
        }

        return $this->userFactory->create(
            $identity,
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
     * {@inheritDoc}
     */
    public function getRealm(): string
    {
        return $this->config->getRealm();
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
