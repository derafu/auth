<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authorization;

use Derafu\Auth\Contract\AccessRulesInterface;
use Derafu\Auth\Exception\AuthorizationException;
use Mezzio\Authentication\UserInterface;
use Mezzio\Authorization\AuthorizationInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The middleware of the authorization: it lets the request go on if one of the
 * roles of the user is granted, and says why not if none is.
 *
 * It decides as the one of Mezzio does (without a user it is a 401, and with a
 * user it is a 403 unless one of its roles is granted, so a user without roles is
 * never granted), but it does not make a response: it throws an
 * `AuthorizationException` with the code 401 or 403. The application answers it
 * like any other error (see the error pages of `derafu/http`): an error page in
 * HTML for a browser, and a problem in JSON for a client of the API, with the
 * status and the title that the code says. The message says what is needed, so
 * the user knows which role to ask for.
 */
final class AuthorizationMiddleware implements MiddlewareInterface
{
    /**
     * Creates the middleware.
     *
     * @param AuthorizationInterface $authorization Who is granted.
     * @param AccessRulesInterface $rules The rules of access, that know which
     * roles a request needs (to say them).
     */
    public function __construct(
        private readonly AuthorizationInterface $authorization,
        private readonly AccessRulesInterface $rules
    ) {
    }

    /**
     * {@inheritDoc}
     *
     * @throws AuthorizationException With the code 401 if there is no user, and
     * with the code 403 if none of the roles of the user is granted.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();

        $user = $request->getAttribute(UserInterface::class, false);
        if (!$user instanceof UserInterface) {
            throw new AuthorizationException(
                ['You must be authenticated to access {path}.', 'path' => $path],
                401
            );
        }

        foreach ($user->getRoles() as $role) {
            if ($this->authorization->isGranted($role, $request)) {
                return $handler->handle($request);
            }
        }

        $roles = $this->rules->requiredRoles($request);

        // Nothing is required but a user: the user has no roles, and a user
        // without roles is never granted.
        if ($roles === []) {
            throw new AuthorizationException(
                ['You do not have access to {path}: your user has no roles.', 'path' => $path],
                403
            );
        }

        throw new AuthorizationException(
            [
                'You do not have access to {path}. These roles give access: {roles}.',
                'path' => $path,
                'roles' => implode(', ', $roles),
            ],
            403
        );
    }
}
