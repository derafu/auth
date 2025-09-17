<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak;

use Derafu\Auth\Contract\AuthorizationInterface;
use Mezzio\Authentication\UserInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Keycloak authorization implementation.
 *
 * This class handles role-based authorization using Keycloak user roles.
 */
class KeycloakAuthorization implements AuthorizationInterface
{
    /**
     * {@inheritDoc}
     */
    public function isGranted(string $role, ServerRequestInterface $request): bool
    {
        $user = $this->getUserFromRequest($request);

        if (!$user) {
            return false;
        }

        $userRoles = iterator_to_array($user->getRoles());

        return in_array($role, $userRoles, true);
    }

    /**
     * {@inheritDoc}
     */
    public function isGrantedAny(array $roles, ServerRequestInterface $request): bool
    {
        if (empty($roles)) {
            return false;
        }

        $user = $this->getUserFromRequest($request);

        if (!$user) {
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
     * {@inheritDoc}
     */
    public function isGrantedAll(array $roles, ServerRequestInterface $request): bool
    {
        if (empty($roles)) {
            return true;
        }

        $user = $this->getUserFromRequest($request);

        if (!$user) {
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

    /**
     * Gets the user from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return UserInterface|null The user or null if not found.
     */
    private function getUserFromRequest(ServerRequestInterface $request): ?UserInterface
    {
        $user = $request->getAttribute('user');

        return $user instanceof UserInterface ? $user : null;
    }
}
