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

use Derafu\Translation\Contract\HeadersAwareInterface;
use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Translation\Exception\Core\TranslatableException;
use Derafu\Translation\Trait\HeadersAwareTrait;
use Exception;

/**
 * Exception thrown when authentication fails.
 *
 * It carries the headers of the response (`WWW-Authenticate`, `Retry-After`),
 * through `HeadersAwareInterface` of `derafu/translation`: this package does not
 * depend on one of HTTP, so it can not build the response itself, but whoever
 * catches the exception and does (`derafu/http`'s `ProblemFactory`, for one) can
 * read them from it.
 */
class AuthenticationException extends TranslatableException implements HeadersAwareInterface
{
    use HeadersAwareTrait;

    /**
     * Creates a new authentication exception.
     *
     * @param string|array<array-key, mixed>|TranslatableInterface $message The exception message:
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
