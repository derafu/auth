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

use Derafu\Auth\Contract\KeycloakUserRepositoryInterface;
use Derafu\Auth\Contract\UserInterface;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;

/**
 * An application-owned implementation that records contract consumption while
 * delegating operations to the real backend configured by the package YAML.
 */
final class ApplicationKeycloakUserRepository implements KeycloakUserRepositoryInterface
{
    /**
     * @var list<string> Names of operations performed through this replacement.
     */
    public array $calls = [];

    /**
     * @param KeycloakUserRepositoryInterface $inner The real backend supplied by YAML decoration.
     */
    public function __construct(private readonly KeycloakUserRepositoryInterface $inner)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(string $credential, ?string $password = null): ?MezzioUserInterface
    {
        $this->calls[] = 'authenticate';

        return $this->inner->authenticate($credential, $password);
    }

    /**
     * {@inheritDoc}
     */
    public function getUserInfoFromToken(string $accessToken): array
    {
        $this->calls[] = 'getUserInfoFromToken';

        return $this->inner->getUserInfoFromToken($accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function verifyBearerToken(string $accessToken): array
    {
        $this->calls[] = 'verifyBearerToken';

        return $this->inner->verifyBearerToken($accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function exchangeCodeForToken(string $code, ?string $pkceCode = null): array
    {
        $this->calls[] = 'exchangeCodeForToken';

        return $this->inner->exchangeCodeForToken($code, $pkceCode);
    }

    /**
     * {@inheritDoc}
     */
    public function refreshToken(string $refreshToken): array
    {
        $this->calls[] = 'refreshToken';

        return $this->inner->refreshToken($refreshToken);
    }

    /**
     * {@inheritDoc}
     */
    public function requestOfflineToken(string $username, string $password, ?string $otp = null): array
    {
        $this->calls[] = 'requestOfflineToken';

        return $this->inner->requestOfflineToken($username, $password, $otp);
    }

    /**
     * {@inheritDoc}
     */
    public function createAuthorizationUrl(array $options = []): string
    {
        $this->calls[] = 'createAuthorizationUrl';

        return $this->inner->createAuthorizationUrl($options);
    }

    /**
     * {@inheritDoc}
     */
    public function getNonce(): string
    {
        $this->calls[] = 'getNonce';

        return $this->inner->getNonce();
    }

    /**
     * {@inheritDoc}
     */
    public function getPkceCode(): ?string
    {
        $this->calls[] = 'getPkceCode';

        return $this->inner->getPkceCode();
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
    public function getLogoutUrl(?string $idToken = null, string $logoutRedirectPath = '/'): string
    {
        $this->calls[] = 'getLogoutUrl';

        return $this->inner->getLogoutUrl($idToken, $logoutRedirectPath);
    }

    /**
     * {@inheritDoc}
     */
    public function getState(): string
    {
        $this->calls[] = 'getState';

        return $this->inner->getState();
    }

    /**
     * {@inheritDoc}
     */
    public function isTokenValid(string $accessToken): bool
    {
        $this->calls[] = 'isTokenValid';

        return $this->inner->isTokenValid($accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function createUser(array $userInfo, ?string $client = null): UserInterface
    {
        $this->calls[] = 'createUser';

        return $this->inner->createUser($userInfo, $client);
    }

    /**
     * {@inheritDoc}
     */
    public function getRealm(): string
    {
        $this->calls[] = 'getRealm';

        return $this->inner->getRealm();
    }
}
