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
use Derafu\Auth\Exception\AuthenticationException;
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
     *
     * The session is due when it does not say when the user was stored (it was
     * made before the time was kept, or `forgetCheck()` was called), and when
     * `$interval` seconds passed since then. Without an interval there is
     * nothing else to ask again for.
     */
    public function isRefreshDue(SessionInterface $session, ?int $interval): bool
    {
        $checkedAt = $session->get('auth_checked_at');

        if ($checkedAt === null) {
            return true;
        }

        return $interval !== null && (int) $checkedAt + $interval <= time();
    }

    /**
     * Forgets when the user was last asked to the provider, so the next
     * request asks again whatever the interval says.
     *
     * @param SessionInterface $session The session.
     */
    public function forgetCheck(SessionInterface $session): void
    {
        $session->unset('auth_checked_at');
    }

    /**
     * {@inheritDoc}
     *
     * The session of `Mezzio\Session\SessionMiddleware` (`LazySession`) is
     * renewed in place and persisted with its new identifier. A session that
     * answers with another instance (`Mezzio\Session\Session` does, it is
     * immutable) would not be renewed for the request that is being handled, and
     * that must not go unnoticed.
     */
    public function regenerate(SessionInterface $session): void
    {
        if ($session->regenerate() !== $session) {
            throw new AuthenticationException(
                'The session can not be renewed in place: use the session of Mezzio\\Session\\SessionMiddleware.',
                500
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function storeUserInfo(SessionInterface $session, array $userInfo): void
    {
        $session->set('user', $userInfo);
        $session->set('auth_checked_at', time());
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
        $session->unset('auth_checked_at');
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
