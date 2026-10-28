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

use Derafu\Auth\Contract\PasswordUserRepositoryInterface;
use Derafu\Auth\Contract\UserInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationPasswordUserRepository implements PasswordUserRepositoryInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param PasswordUserRepositoryInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly PasswordUserRepositoryInterface $inner)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(string $credential, ?string $password = null): ?UserInterface
    {
        $this->calls[] = 'authenticate';

        return $this->inner->authenticate($credential, $password);
    }

    /**
     * {@inheritDoc}
     */
    public function find(string $identity): ?UserInterface
    {
        $this->calls[] = 'find';

        return $this->inner->find($identity);
    }
}
