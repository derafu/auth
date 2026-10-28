<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;

/**
 * Provides Keycloak authentication and OAuth/OIDC operations used by the
 * web, API and account services. Authentication credentials are access
 * tokens; protocol operations retain their own validation and failure
 * contracts.
 */
interface KeycloakUserRepositoryInterface extends UserRepositoryInterface
{
    /**
     * Authenticates an access token and loads its user's current information.
     *
     * @param string $credential The access token to verify.
     * @param string|null $password Ignored: this operation authenticates a token.
     * @return MezzioUserInterface|null The user, or null if authentication is rejected.
     * @throws ProviderUnavailableException If Keycloak's user information cannot be obtained.
     */
    public function authenticate(string $credential, ?string $password = null): ?MezzioUserInterface;

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
     * @throws ProviderUnavailableException If Keycloak cannot provide a usable response.
     */
    public function getUserInfoFromToken(string $accessToken): array;

    /**
     * Verifies the access token that a client of the API sends: what the token
     * says (see `KeycloakTokenVerifierInterface::verifyBearerToken()`) and, unless it is
     * turned off in the configuration, that Keycloak says that it is active (token introspection). The first is done before the second, so a token that is not
     * valid does not cost a request to Keycloak.
     *
     * @param string $accessToken The access token.
     * @return array<string, mixed> The claims of the token.
     * @throws AuthenticationException If the token is not valid, or it is not
     * active.
     * @throws ProviderUnavailableException If Keycloak can not be asked whether
     * the token is active: the token is not accepted without knowing.
     */
    public function verifyBearerToken(string $accessToken): array;

    /**
     * Exchanges an authorization code for an access token.
     *
     * @param string $code The authorization code.
     * @param string|null $pkceCode The PKCE code (the verifier) of the login.
     * @return array<string, mixed> The token information.
     * @throws AuthenticationException If code exchange fails.
     */
    public function exchangeCodeForToken(string $code, ?string $pkceCode = null): array;

    /**
     * Refreshes an access token using a refresh token.
     *
     * @param string $refreshToken The refresh token.
     * @return array<string, mixed> The new token information.
     * @throws AuthenticationException If token refresh fails.
     * @throws ProviderUnavailableException If Keycloak cannot provide a usable response.
     */
    public function refreshToken(string $refreshToken): array;

    /**
     * Asks Keycloak for an offline token for a user that gives its password: the
     * token of the API that the user makes in its profile.
     *
     * Each token is an offline session of its own (the one that a login of a browser
     * makes is the session of the user, which every token of it would share, and
     * revoking one would revoke them all), and the password is asked again, so a
     * session cookie that was stolen is not enough. It needs the client of the
     * application to have the direct access grants (the grant `password`) on.
     *
     * @param string $username The user name (the claim `preferred_username`).
     * @param string $password Its password.
     * @param string|null $otp The code of its second factor, if it has one.
     * @return array{refresh_token: string} What Keycloak gives: `refresh_token` is the offline
     * token.
     * @throws AuthenticationException If Keycloak does not accept the credentials, or
     * it does not give an offline token.
     * @throws ProviderUnavailableException If Keycloak can not answer.
     */
    public function requestOfflineToken(string $username, string $password, ?string $otp = null): array;

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
    public function createAuthorizationUrl(array $options = []): string;

    /**
     * Gets the nonce of the authorization URL that was created last.
     *
     * @return string The nonce.
     */
    public function getNonce(): string;

    /**
     * Gets the PKCE code (the verifier) of the authorization URL that was
     * created last.
     *
     * @return string|null The PKCE code.
     */
    public function getPkceCode(): ?string;

    /**
     * Verifies the ID token of a login.
     *
     * @param string $idToken The ID token.
     * @param string $nonce The nonce of the authorization URL of the login.
     * @return array<string, mixed> The claims of the ID token.
     * @throws AuthenticationException If the ID token is not valid.
     */
    public function verifyIdToken(string $idToken, string $nonce): array;

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
    public function getLogoutUrl(?string $idToken = null, string $logoutRedirectPath = '/'): string;

    /**
     * Gets the state parameter for CSRF protection.
     *
     * @return string The state parameter.
     */
    public function getState(): string;

    /**
     * Validates if an access token is still valid.
     *
     * @param string $accessToken The access token to validate.
     * @return bool True if token is valid, false otherwise.
     * @throws ProviderUnavailableException If token validation cannot reach Keycloak.
     */
    public function isTokenValid(string $accessToken): bool;

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
     * @return UserInterface The user.
     * @throws AuthenticationException If there is no `sub`.
     */
    public function createUser(array $userInfo, ?string $client = null): UserInterface;

    /**
     * The realm of Keycloak where the users of the application have their account.
     *
     * @return string The realm containing the application's users.
     */
    public function getRealm(): string;
}
