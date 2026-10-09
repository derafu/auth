<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication;

use Derafu\Auth\Contract\AuthenticationInterface;
use Mezzio\Authentication\UserInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The middleware of the authentication: it asks who is making the request and
 * puts the user in it, or answers that the request is not authenticated.
 *
 * It does what the one of Mezzio does (that is marked as `@final`, so it is not
 * extended: this one composes the same two calls), with the authentication of the
 * package, and it is the one that a pipeline names, next to the one of the
 * authorization. The user goes in the attribute that has the name of the
 * interface of Mezzio, which is where the authorization and the application look
 * for it.
 */
final class AuthenticationMiddleware implements MiddlewareInterface
{
    /**
     * Creates the middleware.
     *
     * @param AuthenticationInterface $authentication The one entry point of the
     * authentication.
     */
    public function __construct(private readonly AuthenticationInterface $authentication)
    {
    }

    /**
     * {@inheritDoc}
     *
     * A request that needs a user and has none (the authentication says it with
     * `null`) gets the response of its channel: a redirect to the login in the
     * web, a 401 in the API.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $user = $this->authentication->authenticate($request);
        if ($user === null) {
            return $this->authentication->unauthorizedResponse($request);
        }

        return $handler->handle($request->withAttribute(UserInterface::class, $user));
    }
}
