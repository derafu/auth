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

use Mezzio\Authentication\UserInterface as MezzioUserInterface;

/**
 * User interface that extends Mezzio's UserInterface.
 *
 * Provides a clear contract for user entities while maintaining full
 * compatibility with Mezzio's authentication system.
 *
 * @method string getIdentity()
 * @method iterable getRoles()
 * @method mixed getDetail(string $name, mixed $default = null)
 * @method array getDetails()
 */
interface UserInterface extends MezzioUserInterface
{
    /**
     * Checks if the user is anonymous.
     *
     * @return bool True if the user is anonymous, false otherwise.
     */
    public function isAnonymous(): bool;
}
