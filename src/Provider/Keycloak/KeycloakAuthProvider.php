<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak;

use Derafu\Auth\Provider\AuthProvider;

/**
 * The provider of Keycloak: the login is at Keycloak, and its tokens are the ones of the API.
 */
final class KeycloakAuthProvider extends AuthProvider
{
    /**
     * {@inheritDoc}
     */
    public static function name(): string
    {
        return 'keycloak';
    }
}
