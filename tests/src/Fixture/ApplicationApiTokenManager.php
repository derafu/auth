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

use Derafu\Auth\Account\NewApiToken;
use Derafu\Auth\Contract\ApiTokenManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Form\Contract\FormInterface;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationApiTokenManager implements ApiTokenManagerInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param ApiTokenManagerInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly ApiTokenManagerInterface $inner)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function list(SessionInterface $session): array
    {
        $this->calls[] = 'list';

        return $this->inner->list($session);
    }

    /**
     * {@inheritDoc}
     */
    public function form(UserInterface $user, array $data = []): FormInterface
    {
        $this->calls[] = 'form';

        return $this->inner->form($user, $data);
    }

    /**
     * {@inheritDoc}
     */
    public function create(ServerRequestInterface $request, SessionInterface $session): NewApiToken
    {
        $this->calls[] = 'create';

        return $this->inner->create($request, $session);
    }

    /**
     * {@inheritDoc}
     */
    public function revoke(SessionInterface $session, string $id): void
    {
        $this->calls[] = 'revoke';

        $this->inner->revoke($session, $id);
    }
}
