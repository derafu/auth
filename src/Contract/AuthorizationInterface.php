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

use Mezzio\Authorization\AuthorizationInterface as MezzioAuthorizationInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authorization interface that extends Mezzio's AuthorizationInterface.
 *
 * Provides a clear contract for authorization services while maintaining full
 * compatibility with Mezzio's authorization system.
 *
 * @method bool isGranted(string $role, ServerRequestInterface $request)
 */
interface AuthorizationInterface extends MezzioAuthorizationInterface
{
    /**
     * Checks if the user has any of the specified roles.
     *
     * @param array<string> $roles The roles to check.
     * @param ServerRequestInterface $request The request containing user info.
     * @return bool True if user has any of the roles, false otherwise.
     */
    public function isGrantedAny(array $roles, ServerRequestInterface $request): bool;

    /**
     * Checks if the user has all of the specified roles.
     *
     * @param array<string> $roles The roles to check.
     * @param ServerRequestInterface $request The request containing user info.
     * @return bool True if user has all roles, false otherwise.
     */
    public function isGrantedAll(array $roles, ServerRequestInterface $request): bool;
}
