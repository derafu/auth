<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth;

use Derafu\Auth\Contract\SessionManagerInterface;
use Mezzio\Session\SessionInterface;

/**
 * Session manager for authentication providers.
 */
class SessionManager implements SessionManagerInterface
{
    /**
     * {@inheritDoc}
     */
    public function hasAuthInfo(SessionInterface $session): bool
    {
        return $session->has('user');
    }

    /**
     * {@inheritDoc}
     */
    public function clearSession(SessionInterface $session): void
    {
        $this->clearUserInfo($session);
        $this->clearRedirectUrl($session);
    }

    /**
     * {@inheritDoc}
     */
    public function storeUserInfo(SessionInterface $session, array $userInfo): void
    {
        $session->set('user', $userInfo);
    }

    /**
     * {@inheritDoc}
     */
    public function getUserInfo(SessionInterface $session): ?array
    {
        return $session->get('user');
    }

    /**
     * {@inheritDoc}
     */
    public function clearUserInfo(SessionInterface $session): void
    {
        $session->unset('user');
    }

    /**
     * {@inheritDoc}
     */
    public function storeRedirectUrl(SessionInterface $session, string $url): void
    {
        $session->set('auth_redirect', $url);
    }

    /**
     * {@inheritDoc}
     */
    public function getRedirectUrl(SessionInterface $session): ?string
    {
        return $session->get('auth_redirect');
    }

    /**
     * {@inheritDoc}
     */
    public function clearRedirectUrl(SessionInterface $session): void
    {
        $session->unset('auth_redirect');
    }
}
