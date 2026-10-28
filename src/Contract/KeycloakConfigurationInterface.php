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

use Derafu\Auth\Exception\ConfigurationException;

/**
 * Provides Keycloak realm, client, HTTP and channel settings with
 * validation deferred to the channel that uses them.
 */
interface KeycloakConfigurationInterface
{
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
    public function validateWeb(): void;

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
    public function validateApi(): void;

    /**
     * Gets the Keycloak URL.
     *
     * @return string The Keycloak URL.
     */
    public function getKeycloakUrl(): string;

    /**
     * Gets the Keycloak realm.
     *
     * @return string The Keycloak realm.
     */
    public function getRealm(): string;

    /**
     * Gets the Keycloak client ID.
     *
     * @return string The Keycloak client ID.
     */
    public function getClientId(): string;

    /**
     * Gets the Keycloak client secret.
     *
     * @return string The Keycloak client secret.
     */
    public function getClientSecret(): string;

    /**
     * Gets the Keycloak redirect URI.
     *
     * @return string The Keycloak redirect URI.
     */
    public function getRedirectUri(): string;

    /**
     * Gets the Keycloak scopes.
     *
     * @return array<array-key, string> The Keycloak scopes.
     */
    public function getScopes(): array;

    /**
     * Gets the Keycloak callback path.
     *
     * @return string The Keycloak callback path.
     */
    public function getCallbackPath(): string;

    /**
     * Gets the address of the account console of the realm, where the user edits
     * its data.
     *
     * @return string The address.
     */
    public function getAccountUrl(): string;

    /**
     * Gets the Keycloak HTTP client options.
     *
     * The requests have a `User-Agent` that says who makes them (see
     * `getUserAgent()`), unless the application gives its own in
     * `http_client_options.headers`: Keycloak and the servers in front of it have it
     * in their logs.
     *
     * @return array<array-key, mixed> The Keycloak HTTP client options.
     */
    public function getHttpClientOptions(): array;

    /**
     * The `User-Agent` of the requests of the package: `Derafu Auth (<client>)`.
     * Keycloak does not show it in the list of the sessions (it only shows the
     * browsers that it knows), but it is in the logs of the servers.
     */
    public function getUserAgent(): string;

    /**
     * Gets the issuer of the tokens (their `iss`).
     *
     * @return string The URL of the realm, or the issuer that was configured.
     */
    public function getIssuer(): string;

    /**
     * Gets the URL of the realm, where the endpoints of Keycloak are.
     *
     * @return string The URL of the realm.
     */
    public function getRealmUrl(): string;

    /**
     * Whether the logout also ends the session of the user in Keycloak.
     *
     * @return bool True if it does.
     */
    public function isEndSession(): bool;

    /**
     * Gets the URL where Keycloak sends the user after the logout.
     *
     * @param string $logoutRedirectPath The page of the site that follows the
     * logout (the one of the web channel), when no URL was configured.
     * @return string The URL: the one that was configured, or the page that
     * follows the logout in the site of the redirect URI.
     */
    public function getPostLogoutRedirectUri(string $logoutRedirectPath = '/'): string;

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
    public function getApiAudience(): string;

    /**
     * Gets the client that asks Keycloak about the tokens of the API
     * (introspection): the client of the API if it has one of its own, and the
     * client of the application otherwise.
     *
     * @return string The ID of the client.
     */
    public function getApiClientId(): string;

    /**
     * Gets the secret of the client that asks Keycloak about the tokens of the
     * API (see `getApiClientId()`).
     *
     * @return string The secret of the client.
     */
    public function getApiClientSecret(): string;

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
    public function isApiIntrospection(): bool;
}
