<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Derafu\Auth\Provider\AuthProvider;
use LogicException;

/**
 * A provider that an application adds: a class and a tag, nothing of the package
 * changes. It gives nothing, because the test only chooses it.
 */
final class CustomAuthProvider extends AuthProvider
{
    public function __construct()
    {
        $nothing = static fn (): never => throw new LogicException('The custom provider gives nothing.');

        parent::__construct($nothing, $nothing, $nothing, $nothing, $nothing);
    }

    public static function name(): string
    {
        return 'custom';
    }
}
