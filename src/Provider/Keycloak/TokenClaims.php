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

/**
 * What a token of Keycloak says, read without verifying it: it is for tokens that
 * were already verified (the ones that the session keeps) or that only Keycloak
 * can verify (an offline token, which is signed with a secret key of the realm),
 * so what is read is never trusted to let anybody in.
 */
final class TokenClaims
{
    /**
     * The claims of a JWT, or an empty array if it is not one.
     *
     * @return array<string, mixed>
     */
    public static function of(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return [];
        }

        $json = base64_decode(strtr($parts[1], '-_', '+/'), true);
        $claims = $json !== false ? json_decode($json, true) : null;

        return is_array($claims) ? $claims : [];
    }

    /**
     * Whether a token is an offline token: a refresh token that does not depend on
     * the session of the user (`typ` is `Offline`).
     */
    public static function isOffline(string $jwt): bool
    {
        return (self::of($jwt)['typ'] ?? null) === 'Offline';
    }
}
