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
     *
     * The standard fields are the claims of OpenID Connect, which is what the
     * providers give the details with: Keycloak has them, and a database has them
     * when its columns are called like that (or the query of the details renames
     * them). A field that is not there is `null`, never an error.
     */
    public function getName(): ?string
    {
        return $this->text('name') ?? $this->text('preferred_username');
    }

    /**
     * {@inheritDoc}
     */
    public function getGivenName(): ?string
    {
        return $this->text('given_name');
    }

    /**
     * {@inheritDoc}
     */
    public function getFamilyName(): ?string
    {
        return $this->text('family_name');
    }

    /**
     * {@inheritDoc}
     */
    public function getEmail(): ?string
    {
        return $this->text('email');
    }

    /**
     * {@inheritDoc}
     */
    public function isEmailVerified(): bool
    {
        $value = $this->details['email_verified'] ?? null;

        return is_scalar($value) && filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * {@inheritDoc}
     */
    public function getUsername(): ?string
    {
        return $this->text('preferred_username') ?? $this->getEmail();
    }

    /**
     * {@inheritDoc}
     */
    public function getLocale(): ?string
    {
        return $this->text('locale');
    }

    /**
     * The value of a detail as a text, or null if it is not one: it has to be a
     * text or a number, and not empty (so that a field that is blank does not
     * stop a fallback).
     */
    private function text(string $name): ?string
    {
        $value = $this->details[$name] ?? null;

        if (!is_string($value) && !is_int($value) && !is_float($value)) {
            return null;
        }

        $text = trim((string) $value);

        return $text === '' ? null : $text;
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
