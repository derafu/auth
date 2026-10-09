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

use Mezzio\Authentication\AuthenticationInterface as MezzioAuthenticationInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authentication interface that extends Mezzio's AuthenticationInterface.
 *
 * It is the one entry point of the authentication for Mezzio, whose middleware
 * asks it who is making the request. It says it with our own user (the one that
 * can tell it is anonymous), and `null` to a request that needs a user and has
 * none: then Mezzio asks for the response of the unauthorized request.
 */
interface AuthenticationInterface extends MezzioAuthenticationInterface
{
    /**
     * Authenticates a request.
     *
     * @return UserInterface|null The user (the anonymous one if nobody is
     * authenticated and the path does not need one), or null if the path needs a
     * user and there is none.
     */
    public function authenticate(ServerRequestInterface $request): ?UserInterface;

    /**
     * Gets the response to a request that is not authenticated.
     */
    public function unauthorizedResponse(ServerRequestInterface $request): ResponseInterface;
}
