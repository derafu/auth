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

use Derafu\Auth\Contract\DatabaseConfigurationInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationDatabaseConfiguration implements DatabaseConfigurationInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param DatabaseConfigurationInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly DatabaseConfigurationInterface $inner)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        $this->calls[] = 'validate';

        $this->inner->validate();
    }

    /**
     * {@inheritDoc}
     */
    public function getDatabaseUrl(): string
    {
        $this->calls[] = 'getDatabaseUrl';

        return $this->inner->getDatabaseUrl();
    }

    /**
     * {@inheritDoc}
     */
    public function getUserRepository(): array
    {
        $this->calls[] = 'getUserRepository';

        return $this->inner->getUserRepository();
    }

    /**
     * {@inheritDoc}
     */
    public function getUserIdentityField(): string
    {
        $this->calls[] = 'getUserIdentityField';

        return $this->inner->getUserIdentityField();
    }

    /**
     * {@inheritDoc}
     */
    public function getUserPasswordField(): string
    {
        $this->calls[] = 'getUserPasswordField';

        return $this->inner->getUserPasswordField();
    }
}
