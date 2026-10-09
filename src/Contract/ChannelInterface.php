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

use Derafu\Auth\Authentication\Identification;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A channel of authentication: how the requests of an area of the site identify
 * themselves, and what is answered to the ones that are not authenticated.
 *
 * The web is a channel (the user has a session, and the answer to who is not
 * authenticated is a redirect to the login) and the API is another (the client
 * sends its credentials in every request, and the answer is a 401). A channel is
 * chosen by the request, and a new one is added by implementing this interface
 * and tagging the service `derafu_auth.channel`, with a priority: the manager
 * of the authentication does not change.
 *
 * What the channel does with a request that it identified is not its business:
 * whether the path asks for a user is decided by the access rules.
 */
interface ChannelInterface
{
    /**
     * The name of the channel (`web`, `api`).
     */
    public function name(): string;

    /**
     * Whether the request is one of the area of this channel.
     */
    public function matches(ServerRequestInterface $request): bool;

    /**
     * Identifies the request: who is asking.
     *
     * @return Identification The user (anonymous when it has no credentials of this
     * channel and the channel is the last word), that the channel has nothing to
     * say (the next channel that matches is asked), or that the request ends here
     * and it is answered by `unauthorizedResponse()` (a logout).
     */
    public function identify(ServerRequestInterface $request): Identification;

    /**
     * Whether the request is one that the channel itself lets through, whatever
     * the access rules say: the way in and the way out (the login and the logout
     * of the web).
     */
    public function isPublic(ServerRequestInterface $request): bool;

    /**
     * The answer to a request that is not authenticated, or that ends in the
     * channel (a logout).
     */
    public function unauthorizedResponse(ServerRequestInterface $request): ResponseInterface;
}
