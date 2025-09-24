<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth;

use Derafu\Auth\Contract\UserInterface;

/**
 * Default user implementation.
 *
 * This class represents a default user and implements our UserInterface
 * to provide user information to the application.
 */
class User implements UserInterface
{
    /**
     * Creates a new default user.
     *
     * @param string $identity The user identity.
     * @param array $roles The user roles.
     * @param array $details The user details.
     */
    public function __construct(
        private readonly string $identity,
        private readonly array $roles = [],
        private array $details = []
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function getIdentity(): string
    {
        return $this->identity;
    }

    /**
     * {@inheritDoc}
     */
    public function getRoles(): iterable
    {
        return $this->roles;
    }

    /**
     * {@inheritDoc}
     */
    public function getDetails(): array
    {
        return $this->details;
    }

    /**
     * {@inheritDoc}
     */
    public function getDetail(string $name, $default = null)
    {
        return $this->details[$name] ?? $default;
    }

    /**
     * {@inheritDoc}
     */
    public function isAnonymous(): bool
    {
        return false; // Default users must be always authenticated, never anonymous.
    }

    /**
     * {@inheritDoc}
     */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles(), true);
    }

    /**
     * {@inheritDoc}
     */
    public function hasAnyRole(array $roles): bool
    {
        $userRoles = $this->getRoles();
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
    public function hasAllRoles(array $roles): bool
    {
        return count(array_intersect($roles, $this->getRoles())) === count($roles);
    }
}
