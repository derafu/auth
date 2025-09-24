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
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\User;

/**
 * Keycloak user implementation.
 *
 * This class represents a user authenticated through Keycloak and implements
 * our UserInterface to provide user information to the application.
 */
class KeycloakUser extends User implements UserInterface
{
    /**
     * Creates a new Keycloak user.
     *
     * @param array<string, mixed> $userInfo The user information from Keycloak.
     */
    public function __construct(array $userInfo)
    {
        $identity = $userInfo['sub']
            ?? throw new AuthenticationException('User identity not found in keycloak user info.');

        parent::__construct(
            identity: $identity,
            roles: $this->extractRoles($userInfo),
            details: $userInfo,
        );
    }

    /**
     * Extracts the user roles from the user information.
     *
     * @param array<string, mixed> $userInfo The user information from Keycloak.
     * @return array<string> The user roles.
     */
    private function extractRoles(array $userInfo): array
    {
        $roles = $userInfo['roles'] ?? [];
        $realmAccess = $userInfo['realm_access'] ?? [];
        $resourceAccess = $userInfo['resource_access'] ?? [];

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
     * Gets the user's name.
     *
     * @return string|null The name or null if not available.
     */
    public function getName(): ?string
    {
        return
            $this->getDetail('name')
            ?? $this->getDetail('preferred_username')
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
        return $this->getDetail('given_name') ?? null;
    }

    /**
     * Gets the user's family name.
     *
     * @return string|null The family name or null if not available.
     */
    public function getFamilyName(): ?string
    {
        return $this->getDetail('family_name') ?? null;
    }

    /**
     * Gets the user's email address.
     *
     * @return string|null The email address or null if not available.
     */
    public function getEmail(): ?string
    {
        return $this->getDetail('email') ?? null;
    }

    /**
     * Checks if the user's email address is verified.
     *
     * @return bool True if the email address is verified, false otherwise.
     */
    public function isEmailVerified(): bool
    {
        return $this->getDetail('email_verified') ?? false;
    }

    /**
     * Gets the user's username.
     *
     * @return string|null The username or null if not available.
     */
    public function getUsername(): ?string
    {
        return $this->getDetail('preferred_username') ?? $this->getEmail();
    }

    /**
     * Gets the user's locale.
     *
     * @return string|null The locale or null if not available.
     */
    public function getLocale(): ?string
    {
        return $this->getDetail('locale') ?? null;
    }
}
