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

use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Translation\Exception\Core\TranslatableException;
use Exception;

/**
 * Exception thrown when configuration fails.
 */
class ConfigurationException extends TranslatableException
{
    /**
     * Creates a new configuration exception.
     *
     * @param string|array|TranslatableInterface $message The exception message:
     *   - string: Will be used as both message and translation key.
     *   - array: First element must be string (message), remaining elements are
     *     parameters.
     *   - TranslatableInterface: Will be used directly.
     * @param int $code The exception code.
     * @param Exception|null $previous The previous exception.
     */
    public function __construct(
        string|array|TranslatableInterface $message = '',
        int $code = 0,
        ?Exception $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
