<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization Library.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Account;

/**
 * A token of the API that was just made: its value, that is shown once, and what
 * the provider knows of it (when it was made and when it expires, if the token says
 * it).
 */
final class NewApiToken
{
    /**
     * @param string $value The token. Nothing keeps it.
     * @param int|null $createdAt When it was made (a timestamp), if it is known.
     * @param int|null $expiresAt When it expires (a timestamp), if it has an end.
     */
    public function __construct(
        public readonly string $value,
        public readonly ?int $createdAt = null,
        public readonly ?int $expiresAt = null
    ) {
    }
}
