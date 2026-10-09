<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authentication;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Identification;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * What a channel says about who is asking: a user, nothing, or that the request
 * ends in the channel.
 */
#[CoversClass(Identification::class)]
#[UsesClass(AnonymousUser::class)]
final class IdentificationTest extends TestCase
{
    #[Test]
    public function itCanBeAUser(): void
    {
        $user = new AnonymousUser();
        $identification = Identification::of($user);

        $this->assertSame($user, $identification->user());
        $this->assertFalse($identification->isHalted());
    }

    #[Test]
    public function itCanBeNothing(): void
    {
        $identification = Identification::none();

        $this->assertNull($identification->user());
        $this->assertFalse($identification->isHalted());
    }

    #[Test]
    public function itCanBeTheEndOfTheRequest(): void
    {
        $identification = Identification::halt();

        $this->assertNull($identification->user());
        $this->assertTrue($identification->isHalted());
    }
}
