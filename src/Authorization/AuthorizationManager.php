<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authorization;

use Derafu\Auth\Contract\AccessRulesInterface;
use Derafu\Auth\Contract\AuthorizationInterface;
use Derafu\Auth\Contract\UserInterface;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The manager of the authorization: it decides who is granted, not who is
 * authenticated, which is done before by the manager of the authentication.
 *
 * What a request asks (which roles) is in the access rules, the one authority on
 * who may enter which path. When no role is required the request is granted: it
 * is a public path, or a protected path that only asks the user to be
 * authenticated.
 */
final class AuthorizationManager implements AuthorizationInterface
{
    /**
     * Creates the manager.
     *
     * @param AccessRulesInterface $rules The access rules.
     */
    public function __construct(private readonly AccessRulesInterface $rules)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function isGranted(string $userRole, ServerRequestInterface $request): bool
    {
        $requiredRoles = $this->rules->requiredRoles($request);

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
