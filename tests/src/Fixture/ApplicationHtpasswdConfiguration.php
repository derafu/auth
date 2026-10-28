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

use Derafu\Auth\Contract\HtpasswdConfigurationInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationHtpasswdConfiguration implements HtpasswdConfigurationInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param HtpasswdConfigurationInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly HtpasswdConfigurationInterface $inner)
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
    public function getGroupPath(): string
    {
        $this->calls[] = 'getGroupPath';

        return $this->inner->getGroupPath();
    }

    /**
     * {@inheritDoc}
     */
    public function getHtpasswdPath(): string
    {
        $this->calls[] = 'getHtpasswdPath';

        return $this->inner->getHtpasswdPath();
    }
}
