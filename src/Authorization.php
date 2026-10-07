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

use Derafu\Auth\Contract\AuthorizationInterface;
use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Routing\Contract\RouteMatchInterface;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authorization implementation.
 *
 * It decides who is granted, not who is authenticated: that is done before, by
 * the authentication. The roles that a request requires are:
 *
 *   - The ones of the protected path that matches, if it has roles (the site
 *     decides over the routes that it imports).
 *   - Otherwise, the ones that the matched route declares.
 *
 * When no role is required the request is granted: it is a public path, or a
 * protected path that only asks the user to be authenticated.
 */
final class Authorization implements AuthorizationInterface
{
    /**
     * The attribute name used to store the matched route.
     */
    public const ROUTE_ATTRIBUTE = 'derafu.route';

    /**
     * Creates a new authorization implementation.
     *
     * @param ConfigurationInterface $config The configuration.
     */
    public function __construct(private readonly ConfigurationInterface $config)
    {
    }

    /**
     * Gets the roles that the matched route declares.
     *
     * @param ServerRequestInterface $request The request.
     * @return array<string> The roles, empty if there is no route or it
     * declares none.
     */
    public static function routeRoles(ServerRequestInterface $request): array
    {
        $route = $request->getAttribute(self::ROUTE_ATTRIBUTE);

        return $route instanceof RouteMatchInterface ? $route->getRoles() : [];
    }

    /**
     * {@inheritDoc}
     */
    public function isGranted(string $userRole, ServerRequestInterface $request): bool
    {
        $requiredRoles = $this->config->allowedRoles($request->getUri()->getPath())
            ?: self::routeRoles($request)
        ;

        // Nothing is required: whoever is here was already let in by the
        // authentication.
        if (empty($requiredRoles)) {
            return true;
        }

        return in_array($userRole, $requiredRoles, true);
    }

    /**
     * {@inheritDoc}
     */
    public function isGrantedAny(array $requiredRoles, ServerRequestInterface $request): bool
    {
        // Without a user nothing is granted, whatever is required.
        $user = $this->getUserFromRequest($request);

        if (!$user) {
            return false;
        }

        if (empty($requiredRoles)) {
            return false;
        }

        return $user->hasAnyRole($requiredRoles);
    }

    /**
     * {@inheritDoc}
     */
    public function isGrantedAll(array $requiredRoles, ServerRequestInterface $request): bool
    {
        // Without a user nothing is granted, even when no role is required:
        // being granted all of no roles is for a user, not for nobody.
        $user = $this->getUserFromRequest($request);

        if (!$user) {
            return false;
        }

        if (empty($requiredRoles)) {
            return true;
        }

        return $user->hasAllRoles($requiredRoles);
    }

    /**
     * Gets the user from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return UserInterface|null The user or null if not found.
     */
    protected function getUserFromRequest(ServerRequestInterface $request): ?UserInterface
    {
        // The authentication middleware puts the user in the request with the name of
        // the interface of Mezzio.
        $user = $request->getAttribute(MezzioUserInterface::class);

        return $user instanceof UserInterface ? $user : null;
    }
}
