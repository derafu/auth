<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

/**
 * A wrongly tagged service with a provider name but no authentication contract.
 */
final class InvalidAuthProvider
{
    /**
     * Returns the name used by the production locator's tag indexing.
     *
     * @return string The name selecting this misconfigured service.
     */
    public static function name(): string
    {
        return 'broken';
    }
}
