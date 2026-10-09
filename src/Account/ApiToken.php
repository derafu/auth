<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Account;

/**
 * The data of a token of the API, as the provider says it (never the token).
 */
final class ApiToken
{
    /**
     * @param string $id What identifies the token to revoke it.
     * @param int $createdAt When it was made (Unix time).
     * @param int $lastUsedAt When it was last used (Unix time).
     * @param int $expiresAt When it expires (Unix time).
     * @param string|null $ip The address of who made it.
     * @param string|null $browser The browser of who made it.
     */
    public function __construct(
        public readonly string $id,
        public readonly int $createdAt,
        public readonly int $lastUsedAt,
        public readonly int $expiresAt,
        public readonly ?string $ip = null,
        public readonly ?string $browser = null
    ) {
    }
}
