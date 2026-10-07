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

use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration interface.
 *
 * Provides a consistent interface for all configuration classes across
 * different authentication and authorization providers.
 */
interface ConfigurationInterface
{
    /**
     * The seconds after which the user of a session is asked to the provider
     * again when nothing else says when: a provider that has no token that
     * expires, or a token that has no expiry.
     */
    public const DEFAULT_REFRESH_INTERVAL = 300;

    /**
     * Validates the configuration.
     *
     * @throws ConfigurationException If configuration is invalid.
     */
    public function validate(): void;

    /**
     * Gets a specific configuration value.
     *
     * @param string $key The configuration key.
     * @param mixed $default The default value if key doesn't exist.
     * @return mixed The configuration value.
     */
    public function get(string $key, mixed $default = null): mixed;

    /**
     * Gets the configuration as an array.
     *
     * @return array<string, mixed> The configuration data.
     */
    public function toArray(): array;

    /**
     * Gets the protected paths.
     *
     * @return array<string, array<string>> The protected paths.
     */
    public function getProtectedPaths(): array;

    /**
     * Gets the login path.
     *
     * Must match the logout route in the routing configuration.
     *
     * @return string The login path.
     */
    public function getLoginPath(): string;

    /**
     * Gets the logout path.
     *
     * Must match the logout route in the routing configuration.
     *
     * @return string The logout path.
     */
    public function getLogoutPath(): string;

    /**
     * Gets the login redirect route.
     *
     * Where the user will be redirected after login.
     *
     * @return string The login redirect route.
     */
    public function getLoginRedirectRoute(): string;

    /**
     * Gets the logout redirect route.
     *
     * Where the user will be redirected after logout.
     *
     * @return string The logout redirect route.
     */
    public function getLogoutRedirectRoute(): string;

    /**
     * Gets the unauthorized redirect route.
     *
     * Where the user will be redirected if they are unauthorized.
     *
     * @return string The unauthorized redirect route.
     */
    public function getUnauthorizedRedirectRoute(): string;

    /**
     * Gets whether the authentication is enabled.
     *
     * @return bool Whether the authentication is enabled.
     */
    public function isEnabled(): bool;

    /**
     * Gets every how many seconds the user of a session is asked to the
     * provider again: its roles, and that it still exists.
     *
     * The user of a session is a copy that is made when the user logs in, so a
     * change in the provider (a role that is taken away, a user that is
     * disabled) is seen when the copy is asked again, and not before.
     *
     * @return int|null The seconds, or null when the provider decides: the
     * expiration of the token (Keycloak). A provider that has no token to
     * expire has a default.
     */
    public function getRefreshInterval(): ?int;

    /**
     * Gets the roles that the protected path that matches the given path needs.
     *
     * @param string $path The path to check.
     * @return array<string> The roles, empty if the path is not protected or
     * the protected path asks only for a user.
     */
    public function allowedRoles(string $path): array;

    /**
     * Checks if the given path requires authentication.
     *
     * @param string $path The path to check.
     * @return bool True if authentication is required, false otherwise.
     */
    public function requiresAuth(string $path): bool;
}
