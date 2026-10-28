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

use Derafu\Auth\Contract\KeycloakAccountClientInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationKeycloakAccountClient implements KeycloakAccountClientInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param KeycloakAccountClientInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly KeycloakAccountClientInterface $inner)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function tokens(string $accessToken): array
    {
        $this->calls[] = 'tokens';

        return $this->inner->tokens($accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function hasSecondFactor(string $accessToken): bool
    {
        $this->calls[] = 'hasSecondFactor';

        return $this->inner->hasSecondFactor($accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function session(string $accessToken, string $id): ?array
    {
        $this->calls[] = 'session';

        return $this->inner->session($accessToken, $id);
    }

    /**
     * {@inheritDoc}
     */
    public function revoke(string $accessToken, string $id): void
    {
        $this->calls[] = 'revoke';

        $this->inner->revoke($accessToken, $id);
    }
}
