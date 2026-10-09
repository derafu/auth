<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication\Channel\Api\Scheme;

use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\UserInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The scheme `Bearer` (RFC 6750): a token that the client got somewhere else.
 *
 * What a token is, and how it is verified, is of the provider: the scheme of each
 * one extends this and says how (`authenticateToken()`). What is the same is the
 * challenge: `Bearer realm="..."`, and `error="invalid_token"` when a token was
 * sent and was not valid (nothing when no credentials were sent).
 */
abstract class BearerScheme implements ApiSchemeInterface
{
    /**
     * {@inheritDoc}
     */
    public function scheme(): string
    {
        return 'Bearer';
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request, string $credentials): ?UserInterface
    {
        return $this->authenticateToken($credentials);
    }

    /**
     * {@inheritDoc}
     *
     * It is always sent: a browser does not open a window for `Bearer`.
     */
    public function challenge(ServerRequestInterface $request, string $realm, bool $credentialsSent): ?string
    {
        return sprintf('%s realm="%s"', $this->scheme(), $realm)
            . ($credentialsSent ? ', error="invalid_token"' : '')
        ;
    }

    /**
     * Authenticates the user of a token.
     *
     * @return UserInterface|null The user, or null if the token is not valid.
     */
    abstract protected function authenticateToken(string $token): ?UserInterface;
}
