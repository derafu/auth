<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Derafu\Auth\Authentication\Identification;
use Derafu\Auth\Contract\ChannelInterface;
use Laminas\Diactoros\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A channel that matches or not, says what it is told, and counts how many times
 * it was asked who is asking. Its response says its name in `X-Channel`.
 */
final class FakeChannel implements ChannelInterface
{
    public int $asked = 0;

    public function __construct(
        private readonly string $name,
        private readonly bool $matches,
        private readonly Identification $identification,
        private readonly bool $public = false
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function matches(ServerRequestInterface $request): bool
    {
        return $this->matches;
    }

    public function identify(ServerRequestInterface $request): Identification
    {
        $this->asked++;

        return $this->identification;
    }

    public function isPublic(ServerRequestInterface $request): bool
    {
        return $this->public;
    }

    public function unauthorizedResponse(ServerRequestInterface $request): ResponseInterface
    {
        return (new Response())->withHeader('X-Channel', $this->name);
    }
}
