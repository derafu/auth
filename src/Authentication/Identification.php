<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication;

use Derafu\Auth\Contract\UserInterface;

/**
 * What a channel says about who is asking: a user, nothing, or that the request
 * ends in the channel.
 */
final class Identification
{
    private function __construct(
        private readonly ?UserInterface $user,
        private readonly bool $halted
    ) {
    }

    /**
     * The channel knows who is asking: this user (it can be the anonymous one).
     */
    public static function of(UserInterface $user): self
    {
        return new self($user, false);
    }

    /**
     * The channel has nothing to say: the next channel that matches is asked.
     */
    public static function none(): self
    {
        return new self(null, false);
    }

    /**
     * The request ends in the channel (a logout): it is answered by the channel,
     * whatever the access rules say.
     */
    public static function halt(): self
    {
        return new self(null, true);
    }

    public function user(): ?UserInterface
    {
        return $this->user;
    }

    public function isHalted(): bool
    {
        return $this->halted;
    }
}
