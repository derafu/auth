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

/**
 * Defines which request paths belong to the API and its authentication realm.
 */
interface ApiConfigurationInterface
{
    /**
     * Returns the configured API path prefixes in their canonical form.
     *
     * An empty list disables API path matching for this configuration.
     *
     * @return list<string> The canonical API path prefixes, in configuration order.
     */
    public function getPaths(): array;

    /**
     * Determines whether a request path belongs to the API.
     *
     * A path matches when it equals a configured prefix or is below that prefix
     * at a path segment boundary; for example, /api matches /api/users, not /apix.
     *
     * @param string $path The request URI path to check.
     * @return bool True if the path belongs to a configured API prefix.
     */
    public function isApiPath(string $path): bool;

    /**
     * Returns the realm identifying the API's authentication protection space.
     *
     * The realm is used in HTTP authentication challenges. It must be suitable
     * for inclusion in a quoted header value, without quotes, backslashes or
     * control characters.
     *
     * @return string The authentication realm.
     */
    public function getRealm(): string;
}
