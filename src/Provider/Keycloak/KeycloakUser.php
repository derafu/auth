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

use Derafu\Auth\Contract\UserInterface;

/**
 * Keycloak user implementation.
 *
 * This class represents a user authenticated through Keycloak and implements
 * our UserInterface to provide user information to the application.
 */
class KeycloakUser implements UserInterface
{
    /**
     * Creates a new Keycloak user.
     *
     * @param array<string, mixed> $userInfo The user information from Keycloak.
     */
    public function __construct(
        private readonly array $userInfo
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function getIdentity(): string
    {
        return
            $this->userInfo['sub']
            ?? $this->userInfo['id']
            ?? $this->userInfo['email']
            ?? 'unknown'
        ;
    }

    /**
     * {@inheritDoc}
     */
    public function getRoles(): iterable
    {
        $roles = $this->userInfo['roles'] ?? [];
        $realmAccess = $this->userInfo['realm_access'] ?? [];
        $resourceAccess = $this->userInfo['resource_access'] ?? [];

        // Add realm roles.
        if (isset($realmAccess['roles']) && is_array($realmAccess['roles'])) {
            $roles = array_merge($roles, $realmAccess['roles']);
        }

        // Add resource roles.
        if (is_array($resourceAccess)) {
            foreach ($resourceAccess as $resource => $access) {
                if (is_array($access) && isset($access['roles']) && is_array($access['roles'])) {
                    $roles = array_merge($roles, $access['roles']);
                }
            }
        }

        return array_unique($roles);
    }

    /**
     * {@inheritDoc}
     */
    public function getDetail(string $name, $default = null)
    {
        return $this->userInfo[$name] ?? $default;
    }

    /**
     * {@inheritDoc}
     */
    public function getDetails(): array
    {
        return $this->userInfo;
    }

    /**
     * {@inheritDoc}
     */
    public function isAnonymous(): bool
    {
        return false; // Keycloak users are always authenticated, never anonymous.
    }

    /**
     * Gets the user's email address.
     *
     * @return string|null The email address or null if not available.
     */
    public function getEmail(): ?string
    {
        return $this->userInfo['email'] ?? null;
    }

    /**
     * Gets the user's name.
     *
     * @return string|null The name or null if not available.
     */
    public function getName(): ?string
    {
        return
            $this->userInfo['name']
            ?? $this->userInfo['preferred_username']
            ?? null
        ;
    }

    /**
     * Gets the user's given name.
     *
     * @return string|null The given name or null if not available.
     */
    public function getGivenName(): ?string
    {
        return $this->userInfo['given_name'] ?? null;
    }

    /**
     * Gets the user's family name.
     *
     * @return string|null The family name or null if not available.
     */
    public function getFamilyName(): ?string
    {
        return $this->userInfo['family_name'] ?? null;
    }

    /**
     * Checks if the user has a specific role.
     *
     * @param string $role The role to check.
     * @return bool True if the user has the role, false otherwise.
     */
    public function hasRole(string $role): bool
    {
        $roles = iterator_to_array($this->getRoles());

        return in_array($role, $roles, true);
    }

    /**
     * Checks if the user has any of the specified roles.
     *
     * @param array<string> $roles The roles to check.
     * @return bool True if the user has any of the roles, false otherwise.
     */
    public function hasAnyRole(array $roles): bool
    {
        $userRoles = iterator_to_array($this->getRoles());
        foreach ($roles as $role) {
            if (in_array($role, $userRoles, true)) {
                return true;
            }
        }

        return false;
    }
}
