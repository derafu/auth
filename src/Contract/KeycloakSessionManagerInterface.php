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

use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use Mezzio\Session\SessionInterface;

/**
 * Extends authentication session management with Keycloak tokens and the
 * state, nonce and PKCE data of an OIDC login.
 */
interface KeycloakSessionManagerInterface extends SessionManagerInterface
{
    /**
     * Forgets the last user check so the next request revalidates the session.
     *
     * @param SessionInterface $session The session whose check time is cleared.
     */
    public function forgetCheck(SessionInterface $session): void;

    /**
     * Stores authentication information in the session.
     *
     * @param SessionInterface $session The session to store the info in.
     * @param array<string, mixed> $tokenInfo The token information to store.
     */
    public function storeAuthInfo(SessionInterface $session, array $tokenInfo): void;

    /**
     * Tells whether the access token expired. A token that has no expiry does
     * not (when it has to be asked again is up to `isRefreshDue()`).
     *
     * @param SessionInterface $session The session.
     * @return bool True if the token has an expiry and it is in the past.
     */
    public function isTokenExpired(SessionInterface $session): bool;

    /**
     * Gets the stored refresh token from the session.
     *
     * @param SessionInterface $session The session to get the token from.
     * @return string|null The refresh token or null if not found.
     * @throws TranslatableInvalidArgumentException If a stored non-null value is not a string.
     */
    public function getRefreshToken(SessionInterface $session): ?string;

    /**
     * Stores the state parameter for CSRF protection.
     *
     * @param SessionInterface $session The session to store the state in.
     * @param string $state The state parameter to store.
     */
    public function storeState(SessionInterface $session, string $state): void;

    /**
     * Gets the stored state parameter from the session.
     *
     * @param SessionInterface $session The session to get the state from.
     * @return string|null The state parameter or null if not found.
     * @throws TranslatableInvalidArgumentException If a stored non-null value is not a string.
     */
    public function getState(SessionInterface $session): ?string;

    /**
     * Stores what the login needs to be finished when the user comes back from
     * Keycloak: the nonce that the ID token must have and the PKCE code (the
     * verifier of the challenge that was sent). The state is stored with
     * `storeState()`.
     *
     * @param SessionInterface $session The session.
     * @param string $nonce The nonce of the authorization URL.
     * @param string|null $pkceCode The PKCE code of the authorization URL.
     */
    public function storeLogin(SessionInterface $session, string $nonce, ?string $pkceCode): void;

    /**
     * Gets the nonce of the login that is in progress.
     *
     * @param SessionInterface $session The session.
     * @return string|null The nonce or null if there is no login in progress.
     * @throws TranslatableInvalidArgumentException If a stored non-null value is not a string.
     */
    public function getNonce(SessionInterface $session): ?string;

    /**
     * Gets the PKCE code (the verifier) of the login that is in progress.
     *
     * @param SessionInterface $session The session.
     * @return string|null The PKCE code.
     * @throws TranslatableInvalidArgumentException If a stored non-null value is not a string.
     */
    public function getPkceCode(SessionInterface $session): ?string;

    /**
     * Gets the ID token of the session: what Keycloak needs to end the session
     * of the user.
     *
     * @param SessionInterface $session The session.
     * @return string|null The ID token.
     * @throws TranslatableInvalidArgumentException If a stored non-null value is not a string.
     */
    public function getIdToken(SessionInterface $session): ?string;

    /**
     * Gets the access token that the session has (the one of the user, that is
     * renewed when it is due).
     *
     * @param SessionInterface $session The session.
     * @return string|null The access token, or null if there is none.
     */
    public function getAccessToken(SessionInterface $session): ?string;

    /**
     * Clears what the login in progress stored: the state, the nonce and the PKCE
     * code.
     *
     * @param SessionInterface $session The session to clear.
     */
    public function clearState(SessionInterface $session): void;
}
