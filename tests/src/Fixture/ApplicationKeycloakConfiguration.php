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

use Derafu\Auth\Contract\KeycloakConfigurationInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationKeycloakConfiguration implements KeycloakConfigurationInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param KeycloakConfigurationInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly KeycloakConfigurationInterface $inner)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function validateWeb(): void
    {
        $this->calls[] = 'validateWeb';

        $this->inner->validateWeb();
    }

    /**
     * {@inheritDoc}
     */
    public function validateApi(): void
    {
        $this->calls[] = 'validateApi';

        $this->inner->validateApi();
    }

    /**
     * {@inheritDoc}
     */
    public function getKeycloakUrl(): string
    {
        $this->calls[] = 'getKeycloakUrl';

        return $this->inner->getKeycloakUrl();
    }

    /**
     * {@inheritDoc}
     */
    public function getRealm(): string
    {
        $this->calls[] = 'getRealm';

        return $this->inner->getRealm();
    }

    /**
     * {@inheritDoc}
     */
    public function getClientId(): string
    {
        $this->calls[] = 'getClientId';

        return $this->inner->getClientId();
    }

    /**
     * {@inheritDoc}
     */
    public function getClientSecret(): string
    {
        $this->calls[] = 'getClientSecret';

        return $this->inner->getClientSecret();
    }

    /**
     * {@inheritDoc}
     */
    public function getRedirectUri(): string
    {
        $this->calls[] = 'getRedirectUri';

        return $this->inner->getRedirectUri();
    }

    /**
     * {@inheritDoc}
     */
    public function getScopes(): array
    {
        $this->calls[] = 'getScopes';

        return $this->inner->getScopes();
    }

    /**
     * {@inheritDoc}
     */
    public function getCallbackPath(): string
    {
        $this->calls[] = 'getCallbackPath';

        return $this->inner->getCallbackPath();
    }

    /**
     * {@inheritDoc}
     */
    public function getAccountUrl(): string
    {
        $this->calls[] = 'getAccountUrl';

        return $this->inner->getAccountUrl();
    }

    /**
     * {@inheritDoc}
     */
    public function getHttpClientOptions(): array
    {
        $this->calls[] = 'getHttpClientOptions';

        return $this->inner->getHttpClientOptions();
    }

    /**
     * {@inheritDoc}
     */
    public function getUserAgent(): string
    {
        $this->calls[] = 'getUserAgent';

        return $this->inner->getUserAgent();
    }

    /**
     * {@inheritDoc}
     */
    public function getIssuer(): string
    {
        $this->calls[] = 'getIssuer';

        return $this->inner->getIssuer();
    }

    /**
     * {@inheritDoc}
     */
    public function getRealmUrl(): string
    {
        $this->calls[] = 'getRealmUrl';

        return $this->inner->getRealmUrl();
    }

    /**
     * {@inheritDoc}
     */
    public function isEndSession(): bool
    {
        $this->calls[] = 'isEndSession';

        return $this->inner->isEndSession();
    }

    /**
     * {@inheritDoc}
     */
    public function getPostLogoutRedirectUri(string $logoutRedirectPath = '/'): string
    {
        $this->calls[] = 'getPostLogoutRedirectUri';

        return $this->inner->getPostLogoutRedirectUri($logoutRedirectPath);
    }

    /**
     * {@inheritDoc}
     */
    public function getApiAudience(): string
    {
        $this->calls[] = 'getApiAudience';

        return $this->inner->getApiAudience();
    }

    /**
     * {@inheritDoc}
     */
    public function getApiClientId(): string
    {
        $this->calls[] = 'getApiClientId';

        return $this->inner->getApiClientId();
    }

    /**
     * {@inheritDoc}
     */
    public function getApiClientSecret(): string
    {
        $this->calls[] = 'getApiClientSecret';

        return $this->inner->getApiClientSecret();
    }

    /**
     * {@inheritDoc}
     */
    public function isApiIntrospection(): bool
    {
        $this->calls[] = 'isApiIntrospection';

        return $this->inner->isApiIntrospection();
    }
}
