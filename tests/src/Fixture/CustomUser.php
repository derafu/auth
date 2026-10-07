<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Derafu\Auth\User;

/**
 * A user of an application that has a field of its own (a Chilean RUT) and a
 * getter for it, on top of the standard ones.
 */
final class CustomUser extends User
{
    public function getRut(): ?string
    {
        $rut = $this->getDetail('rut');

        return is_string($rut) ? $rut : null;
    }
}
