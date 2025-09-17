<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Mezzio\Authentication\UserInterface;
use Mezzio\Authentication\UserRepositoryInterface as MezzioUserRepositoryInterface;

/**
 * User repository interface that extends Mezzio's UserRepositoryInterface.
 *
 * Provides a clear contract for user repositories while maintaining full
 * compatibility with Mezzio's authentication system.
 *
 * @method UserInterface|null authenticate(string $credential, string|null $password = null)
 */
interface UserRepositoryInterface extends MezzioUserRepositoryInterface
{
}
