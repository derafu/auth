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
 * user it is a 403 unless one of its roles is granted), except that when the
 * request needs no role (a public path, or one that only asks for a user) the
 * user is let in even if it has none. It does not make a response: it throws an
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

        $roles = $this->rules->requiredRoles($request);

        // No role is required: the path is public, or it only asks for a user,
        // and there is one. Who has no roles is let in as anybody else.
        if ($roles === []) {
            return $handler->handle($request);
        }

        foreach ($user->getRoles() as $role) {
            if ($this->authorization->isGranted($role, $request)) {
                return $handler->handle($request);
            }
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
