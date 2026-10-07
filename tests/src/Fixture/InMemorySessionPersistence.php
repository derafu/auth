<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Mezzio\Session\Session;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionPersistenceInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A session persistence that keeps the sessions in memory, with the same
 * contract as the one of PHP (`PhpSessionPersistence`): the identifier comes in
 * the cookie `sid` of the request, a session that was regenerated is persisted
 * with a new identifier and the old one is destroyed, and the identifier that
 * the client has to use is given in the header `X-Session-Id` of the response.
 */
final class InMemorySessionPersistence implements SessionPersistenceInterface
{
    /**
     * The data of the sessions, by identifier.
     *
     * @var array<string, array<string, mixed>>
     */
    public array $store = [];

    public function initializeSessionFromRequest(ServerRequestInterface $request): SessionInterface
    {
        $id = (string) ($request->getCookieParams()['sid'] ?? '');

        return new Session($id !== '' ? ($this->store[$id] ?? []) : [], $id);
    }

    public function persistSession(SessionInterface $session, ResponseInterface $response): ResponseInterface
    {
        $id = $session->getId();

        if ($session->isRegenerated() || $id === '') {
            unset($this->store[$id]);
            $id = bin2hex(random_bytes(16));
        }

        $this->store[$id] = $session->toArray();

        return $response->withHeader('X-Session-Id', $id);
    }
}
