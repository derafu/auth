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

/**
 * Verifies Keycloak token signatures and claims, distinguishing login tokens from API bearer tokens.
 */
interface KeycloakTokenVerifierInterface
{
    /**
     * Verifies the signature, issuer, expiration, client audience and login nonce
     * of an ID token.
     *
     * @param string $idToken The encoded ID token returned for the login.
     * @param string $nonce The nonce stored when that login was started.
     * @return array<string, mixed> The verified claims.
     * @throws AuthenticationException If verification fails, including when the
     * realm's signing keys cannot be read.
     */
    public function verifyIdToken(string $idToken, string $nonce): array;

    /**
     * Verifies an access token.
     *
     * @param string $accessToken The access token.
     * @return array<string, mixed> The claims of the token.
     * @throws AuthenticationException If the token is not valid.
     */
    public function verifyAccessToken(string $accessToken): array;

    /**
     * Verifies the access token that a client of the API sends.
     *
     * The token is the one of a service (`client_credentials`) or of a person,
     * that was given to any client of the realm: what makes it valid for this API
     * is its audience, so it must have the configured one (see
     * `KeycloakConfigurationInterface::getApiAudience()`). Apart from the signature, the
     * issuer and the expiration, it must be an access token (an ID token, a
     * refresh token or an offline token are not one, they must not open the API by
     * themselves: an offline token is exchanged for an access token first, see
     * `KeycloakBearerScheme`).
     *
     * It is verified only by what it says: a token that was not revoked, of a
     * user that was disabled after it was given, is valid until it expires.
     *
     * @param string $accessToken The access token.
     * @param string $audience The audience that it must have.
     * @return array<string, mixed> The claims of the token.
     * @throws AuthenticationException If the token is not valid.
     */
    public function verifyBearerToken(string $accessToken, string $audience): array;
}
