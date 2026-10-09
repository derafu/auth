<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Psr\Http\Message\ServerRequestInterface;

/**
 * The rules of access: who may enter which path.
 *
 * It is what authorization knows, and it is independent of how a request is
 * identified (the channels) and of where the users are (the providers). The
 * authentication only asks it one thing, whether a request needs a user, to say
 * "not authenticated" when it does and there is none; the authorization asks it
 * which roles a request needs.
 */
interface AccessRulesInterface
{
    /**
     * Whether the rules are enforced. With false no protected path asks for a
     * user (a route that declares roles still does).
     */
    public function isEnabled(): bool;

    /**
     * The protected paths: a list of paths, or a map from a path to its roles.
     *
     * @return array<int|string, mixed>
     */
    public function getProtectedPaths(): array;

    /**
     * Whether a request needs an authenticated user: its path is protected, or
     * the route that it matched declares roles.
     */
    public function requiresAuthentication(ServerRequestInterface $request): bool;

    /**
     * The roles that a request needs: the ones of the most specific protected path
     * that it is under, if it has roles, and otherwise the ones that the matched
     * route declares.
     *
     * @return array<string> The roles, empty if none is needed.
     */
    public function requiredRoles(ServerRequestInterface $request): array;
}
