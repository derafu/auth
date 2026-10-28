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

use Derafu\Auth\Contract\KeycloakSessionManagerInterface;
use Mezzio\Session\SessionInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationKeycloakSessionManager implements KeycloakSessionManagerInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param KeycloakSessionManagerInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly KeycloakSessionManagerInterface $inner)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function forgetCheck(SessionInterface $session): void
    {
        $this->calls[] = 'forgetCheck';

        $this->inner->forgetCheck($session);
    }

    /**
     * {@inheritDoc}
     */
    public function storeAuthInfo(SessionInterface $session, array $tokenInfo): void
    {
        $this->calls[] = 'storeAuthInfo';

        $this->inner->storeAuthInfo($session, $tokenInfo);
    }

    /**
     * {@inheritDoc}
     */
    public function isTokenExpired(SessionInterface $session): bool
    {
        $this->calls[] = 'isTokenExpired';

        return $this->inner->isTokenExpired($session);
    }

    /**
     * {@inheritDoc}
     */
    public function getRefreshToken(SessionInterface $session): ?string
    {
        $this->calls[] = 'getRefreshToken';

        return $this->inner->getRefreshToken($session);
    }

    /**
     * {@inheritDoc}
     */
    public function storeState(SessionInterface $session, string $state): void
    {
        $this->calls[] = 'storeState';

        $this->inner->storeState($session, $state);
    }

    /**
     * {@inheritDoc}
     */
    public function getState(SessionInterface $session): ?string
    {
        $this->calls[] = 'getState';

        return $this->inner->getState($session);
    }

    /**
     * {@inheritDoc}
     */
    public function storeLogin(SessionInterface $session, string $nonce, ?string $pkceCode): void
    {
        $this->calls[] = 'storeLogin';

        $this->inner->storeLogin($session, $nonce, $pkceCode);
    }

    /**
     * {@inheritDoc}
     */
    public function getNonce(SessionInterface $session): ?string
    {
        $this->calls[] = 'getNonce';

        return $this->inner->getNonce($session);
    }

    /**
     * {@inheritDoc}
     */
    public function getPkceCode(SessionInterface $session): ?string
    {
        $this->calls[] = 'getPkceCode';

        return $this->inner->getPkceCode($session);
    }

    /**
     * {@inheritDoc}
     */
    public function getIdToken(SessionInterface $session): ?string
    {
        $this->calls[] = 'getIdToken';

        return $this->inner->getIdToken($session);
    }

    /**
     * {@inheritDoc}
     */
    public function getAccessToken(SessionInterface $session): ?string
    {
        $this->calls[] = 'getAccessToken';

        return $this->inner->getAccessToken($session);
    }

    /**
     * {@inheritDoc}
     */
    public function clearState(SessionInterface $session): void
    {
        $this->calls[] = 'clearState';

        $this->inner->clearState($session);
    }

    /**
     * {@inheritDoc}
     */
    public function hasAuthInfo(SessionInterface $session): bool
    {
        $this->calls[] = 'hasAuthInfo';

        return $this->inner->hasAuthInfo($session);
    }

    /**
     * {@inheritDoc}
     */
    public function storeUserInfo(SessionInterface $session, array $userInfo): void
    {
        $this->calls[] = 'storeUserInfo';

        $this->inner->storeUserInfo($session, $userInfo);
    }

    /**
     * {@inheritDoc}
     */
    public function getUserInfo(SessionInterface $session): ?array
    {
        $this->calls[] = 'getUserInfo';

        return $this->inner->getUserInfo($session);
    }

    /**
     * {@inheritDoc}
     */
    public function clearUserInfo(SessionInterface $session): void
    {
        $this->calls[] = 'clearUserInfo';

        $this->inner->clearUserInfo($session);
    }

    /**
     * {@inheritDoc}
     */
    public function isRefreshDue(SessionInterface $session, ?int $interval): bool
    {
        $this->calls[] = 'isRefreshDue';

        return $this->inner->isRefreshDue($session, $interval);
    }

    /**
     * {@inheritDoc}
     */
    public function clearSession(SessionInterface $session): void
    {
        $this->calls[] = 'clearSession';

        $this->inner->clearSession($session);
    }

    /**
     * {@inheritDoc}
     */
    public function regenerate(SessionInterface $session): void
    {
        $this->calls[] = 'regenerate';

        $this->inner->regenerate($session);
    }

    /**
     * {@inheritDoc}
     */
    public function storeRedirectUrl(SessionInterface $session, string $url): void
    {
        $this->calls[] = 'storeRedirectUrl';

        $this->inner->storeRedirectUrl($session, $url);
    }

    /**
     * {@inheritDoc}
     */
    public function getRedirectUrl(SessionInterface $session): ?string
    {
        $this->calls[] = 'getRedirectUrl';

        return $this->inner->getRedirectUrl($session);
    }

    /**
     * {@inheritDoc}
     */
    public function clearRedirectUrl(SessionInterface $session): void
    {
        $this->calls[] = 'clearRedirectUrl';

        $this->inner->clearRedirectUrl($session);
    }
}
