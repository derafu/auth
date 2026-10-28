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

use Derafu\Auth\Account\ApiToken;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;

/**
 * Accesses the authenticated user's Keycloak account sessions and
 * credentials with that user's access token.
 */
interface KeycloakAccountClientInterface
{
    /**
     * The tokens of the API of the user: its offline sessions of this client.
     *
     * @param string $accessToken The authenticated user's access token.
     * @return list<ApiToken> The newest first.
     * @throws AuthenticationException If Keycloak does not let the user see them.
     * @throws ProviderUnavailableException If Keycloak does not answer.
     */
    public function tokens(string $accessToken): array;

    /**
     * Whether the user has a second factor (a code of an app) set up: the account API
     * lists the kinds of credentials of the user, with the ones that it has.
     *
     * @param string $accessToken The authenticated user's access token.
     * @return bool Whether an OTP credential is configured for the user.
     * @throws AuthenticationException If Keycloak does not let the user see them.
     * @throws ProviderUnavailableException If Keycloak does not answer.
     */
    public function hasSecondFactor(string $accessToken): bool;

    /**
     * What Keycloak says about a session of login of the user.
     *
     * @param string $accessToken The authenticated user's access token.
     * @param string $id The session identifier returned by Keycloak.
     * @return array<string, mixed>|null The session, or null if it is not there.
     * @throws AuthenticationException If Keycloak does not let the user see it.
     * @throws ProviderUnavailableException If Keycloak does not answer.
     */
    public function session(string $accessToken, string $id): ?array;

    /**
     * Revokes a session of the user: the token stops working at once.
     *
     * @param string $accessToken The authenticated user's access token.
     * @param string $id The session identifier returned by Keycloak.
     * @throws AuthenticationException If Keycloak does not let the user do it.
     * @throws ProviderUnavailableException If Keycloak does not answer.
     */
    public function revoke(string $accessToken, string $id): void;
}
