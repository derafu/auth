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

use Derafu\Auth\Contract\KeycloakTokenVerifierInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationKeycloakTokenVerifier implements KeycloakTokenVerifierInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param KeycloakTokenVerifierInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly KeycloakTokenVerifierInterface $inner)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function verifyIdToken(string $idToken, string $nonce): array
    {
        $this->calls[] = 'verifyIdToken';

        return $this->inner->verifyIdToken($idToken, $nonce);
    }

    /**
     * {@inheritDoc}
     */
    public function verifyAccessToken(string $accessToken): array
    {
        $this->calls[] = 'verifyAccessToken';

        return $this->inner->verifyAccessToken($accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function verifyBearerToken(string $accessToken, string $audience): array
    {
        $this->calls[] = 'verifyBearerToken';

        return $this->inner->verifyBearerToken($accessToken, $audience);
    }
}
