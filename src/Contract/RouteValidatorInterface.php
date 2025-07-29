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

/**
 * Interface for route validation.
 *
 * This interface defines the contract for services that can determine which
 * routes require authentication.
 */
interface RouteValidatorInterface
{
    /**
     * Checks if a route requires authentication.
     *
     * @param string $path The route path.
     * @return bool True if authentication is required, false otherwise.
     */
    public function requiresAuth(string $path): bool;

    /**
     * Checks if a path is the authentication callback route.
     *
     * @param string $path The route path.
     * @return bool True if it's the callback route, false otherwise.
     */
    public function isCallbackPath(string $path): bool;

    /**
     * Checks if a path is the logout route.
     *
     * @param string $path The route path.
     * @return bool True if it's the logout route, false otherwise.
     */
    public function isLogoutPath(string $path): bool;

    /**
     * Gets the list of protected routes.
     *
     * @return array<string> The list of protected routes.
     */
    public function getProtectedRoutes(): array;

    /**
     * Gets the authentication callback route.
     *
     * @return string The callback route.
     */
    public function getCallbackRoute(): string;

    /**
     * Gets the logout route.
     *
     * @return string The logout route.
     */
    public function getLogoutRoute(): string;
}
