<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Htpasswd;

use Derafu\Auth\Provider\AuthProvider;

/**
 * The provider of an htpasswd file: the login is a form of the site.
 */
final class HtpasswdAuthProvider extends AuthProvider
{
    /**
     * {@inheritDoc}
     */
    public static function name(): string
    {
        return 'htpasswd';
    }

    /**
     * {@inheritDoc}
     *
     * The login is a page of the site: the user that logs out or is not allowed
     * goes there.
     */
    public function webDefaults(): array
    {
        return [
            'logout_redirect_path' => '/auth/login',
            'unauthorized_redirect_path' => '/auth/login',
        ];
    }
}
