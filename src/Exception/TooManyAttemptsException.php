<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization Library.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Exception;

/**
 * A client that failed too many times is limited: its credentials are not even
 * checked until the limit ends, and what it is told is when to try again (a `429`
 * with `Retry-After`, RFC 6585), not that its credentials are wrong.
 */
class TooManyAttemptsException extends AuthenticationException
{
    /**
     * @param int $retryAfter The seconds until the client can try again.
     */
    public function __construct(private readonly int $retryAfter)
    {
        parent::__construct(
            ['Too many failed login attempts. Try again in {minutes, plural, one {# minute} other {# minutes}}.', 'minutes' => (int) ceil($retryAfter / 60)],
            429
        );
    }

    /**
     * The seconds until the client can try again.
     */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
