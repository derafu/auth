<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Exception;

use Exception;

/**
 * Exception thrown when authorization fails.
 */
class AuthorizationException extends Exception
{
    /**
     * Creates a new authorization exception.
     *
     * @param string $message The exception message.
     * @param int $code The exception code.
     * @param Exception|null $previous The previous exception.
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?Exception $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
