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

    /**
     * Gets the full name of the user (the claim `name`), or its username if it
     * has no name.
     *
     * @return string|null The name, or null if there is none.
     */
    public function getName(): ?string;

    /**
     * Gets the given name of the user (`given_name`).
     *
     * @return string|null The given name, or null if there is none.
     */
    public function getGivenName(): ?string;

    /**
     * Gets the family name of the user (`family_name`).
     *
     * @return string|null The family name, or null if there is none.
     */
    public function getFamilyName(): ?string;

    /**
     * Gets the email of the user (`email`).
     *
     * @return string|null The email, or null if there is none.
     */
    public function getEmail(): ?string;

    /**
     * Tells whether the email of the user was verified (`email_verified`).
     *
     * @return bool True if it was; false if it was not or it is not known.
     */
    public function isEmailVerified(): bool;

    /**
     * Gets the username of the user (`preferred_username`), or its email if it
     * has no username.
     *
     * @return string|null The username, or null if there is none.
     */
    public function getUsername(): ?string;

    /**
     * Gets the locale of the user (`locale`).
     *
     * @return string|null The locale, or null if there is none.
     */
    public function getLocale(): ?string;

    /**
     * Checks if the user has a specific role.
     *
     * @param string $role The role to check.
     * @return bool True if the user has the role, false otherwise.
     */
    public function hasRole(string $role): bool;

    /**
     * Checks if the user has any of the specified roles.
     *
     * @param array<string> $roles The roles to check.
     * @return bool True if the user has any of the roles, false otherwise.
     */
    public function hasAnyRole(array $roles): bool;

    /**
     * Checks if the user has all of the specified roles.
     *
     * @param array<string> $roles The roles to check.
     * @return bool True if the user has all of the roles, false otherwise.
     */
    public function hasAllRoles(array $roles): bool;
}
