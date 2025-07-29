<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Adapter;

use Mezzio\Authentication\UserInterface;
use Mezzio\Authorization\AuthorizationInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Keycloak authorization adapter for Mezzio.
 *
 * This adapter implements Mezzio's AuthorizationInterface to provide role-based
 * authorization using Keycloak user roles.
 */
class KeycloakAuthorizationAdapter implements AuthorizationInterface
{
    /**
     * Creates a new Keycloak authorization adapter.
     */
    public function __construct()
    {
    }

    /**
     * {@inheritDoc}
     */
    public function isGranted(string $role, ServerRequestInterface $request): bool
    {
        $user = $request->getAttribute(UserInterface::class);

        if (!$user instanceof UserInterface) {
            return false;
        }

        // Check if user has the required role.
        $userRoles = iterator_to_array($user->getRoles());

        return in_array($role, $userRoles, true);
    }

    /**
     * Checks if the user has any of the specified roles.
     *
     * @param array<string> $roles The roles to check.
     * @param ServerRequestInterface $request The request.
     * @return bool True if the user has any of the roles, false otherwise.
     */
    public function isGrantedAny(array $roles, ServerRequestInterface $request): bool
    {
        $user = $request->getAttribute(UserInterface::class);

        if (!$user instanceof UserInterface) {
            return false;
        }

        $userRoles = iterator_to_array($user->getRoles());

        foreach ($roles as $role) {
            if (in_array($role, $userRoles, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if the user has all of the specified roles.
     *
     * @param array<string> $roles The roles to check.
     * @param ServerRequestInterface $request The request.
     * @return bool True if the user has all of the roles, false otherwise.
     */
    public function isGrantedAll(array $roles, ServerRequestInterface $request): bool
    {
        $user = $request->getAttribute(UserInterface::class);

        if (!$user instanceof UserInterface) {
            return false;
        }

        $userRoles = iterator_to_array($user->getRoles());

        foreach ($roles as $role) {
            if (!in_array($role, $userRoles, true)) {
                return false;
            }
        }

        return true;
    }
}
