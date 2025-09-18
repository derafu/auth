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
     * The attribute name used to store the matched route.
     */
    public const ROUTE_ATTRIBUTE = 'derafu.route';

    /**
     * Creates a new Keycloak authorization implementation.
     *
     * @param KeycloakConfiguration $config The configuration.
     */
    public function __construct(
        private readonly KeycloakConfiguration $config,
        private readonly string $routeAttribute = self::ROUTE_ATTRIBUTE
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function isGranted(string $userRole, ServerRequestInterface $request): bool
    {
        $path = $request->getUri()->getPath();

        if (!$this->config->requiresAuth($path)) {
            return true;
        }

        $allowedRoles = $this->config->allowedRoles($path);
        if (!empty($allowedRoles)) {
            return in_array($userRole, $allowedRoles);
        }

        $route = $request->getAttribute($this->routeAttribute);

        if (!$route) {
            return true; // If no route is matched, the user is granted.
        }

        return $route->isGranted($userRole);
    }

    /**
     * {@inheritDoc}
     */
    public function isGrantedAny(array $requiredRoles, ServerRequestInterface $request): bool
    {
        $path = $request->getUri()->getPath();

        if (!$this->config->requiresAuth($path)) {
            return true;
        }

        if (empty($requiredRoles)) {
            return false;
        }

        $user = $this->getUserFromRequest($request);

        if (!$user || !$user instanceof KeycloakUser) {
            return false;
        }

        return $user->hasAnyRole($requiredRoles);
    }

    /**
     * {@inheritDoc}
     */
    public function isGrantedAll(array $requiredRoles, ServerRequestInterface $request): bool
    {
        $path = $request->getUri()->getPath();

        if (!$this->config->requiresAuth($path)) {
            return true;
        }

        if (empty($requiredRoles)) {
            return true;
        }

        $user = $this->getUserFromRequest($request);

        if (!$user || !$user instanceof KeycloakUser) {
            return false;
        }

        return $user->hasAllRoles($requiredRoles);
    }

    /**
     * Gets the user from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return UserInterface|null The user or null if not found.
     */
    private function getUserFromRequest(ServerRequestInterface $request): ?UserInterface
    {
        $user = $request->getAttribute(UserInterface::class);

        return $user instanceof UserInterface ? $user : null;
    }
}
