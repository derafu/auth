<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Middleware;

use Derafu\Auth\Exception\AuthorizationException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Authorization middleware for PSR-15.
 *
 * This middleware checks if the authenticated user has the required roles or
 * permissions to access a specific route.
 *
 * Note: This middleware should be used after AuthenticationMiddleware to ensure
 * the user is authenticated.
 */
class AuthorizationMiddleware implements MiddlewareInterface
{
    /**
     * Creates a new authorization middleware.
     *
     * @param array<string,array<string>> $routePermissions Map of routes to
     * required permissions.
     */
    public function __construct(
        private readonly array $routePermissions = []
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $path = $request->getUri()->getPath();
        $user = $request->getAttribute('user');

        // If no user is authenticated, let the authentication middleware handle
        // it.
        if (!$user) {
            return $handler->handle($request);
        }

        // Check if route requires specific permissions.
        $requiredPermissions = $this->getRequiredPermissions($path);
        if (empty($requiredPermissions)) {
            return $handler->handle($request);
        }

        // Check if user has required permissions.
        if (!$this->hasPermissions($user, $requiredPermissions)) {
            throw new AuthorizationException(
                'Access denied. Insufficient permissions for this route.'
            );
        }

        return $handler->handle($request);
    }

    /**
     * Gets the required permissions for a route.
     *
     * @param string $path The route path.
     * @return array<string> The required permissions.
     */
    private function getRequiredPermissions(string $path): array
    {
        foreach ($this->routePermissions as $route => $permissions) {
            if (str_starts_with($path, $route)) {
                return $permissions;
            }
        }

        return [];
    }

    /**
     * Checks if a user has the required permissions.
     *
     * @param array $user The user information.
     * @param array<string> $requiredPermissions The required permissions.
     * @return bool True if user has permissions, false otherwise.
     */
    private function hasPermissions(array $user, array $requiredPermissions): bool
    {
        $userRoles = $user['roles'] ?? [];
        $userPermissions = $user['permissions'] ?? [];

        foreach ($requiredPermissions as $permission) {
            if (
                !in_array($permission, $userRoles)
                && !in_array($permission, $userPermissions)
            ) {
                return false;
            }
        }

        return true;
    }
}
