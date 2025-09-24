<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Mezzio\Session\SessionInterface;

/**
 * Session manager contract for authentication providers.
 *
 * This interface defines the common session management operations
 * that all authentication providers must implement.
 */
interface SessionManagerInterface
{
    /**
     * Checks if authentication information exists in the session.
     *
     * @param SessionInterface $session The session to check.
     * @return bool True if auth info exists, false otherwise.
     */
    public function hasAuthInfo(SessionInterface $session): bool;

    /**
     * Stores user information in the session.
     *
     * @param SessionInterface $session The session to store the info in.
     * @param array<string, mixed> $userInfo The user information to store.
     */
    public function storeUserInfo(SessionInterface $session, array $userInfo): void;

    /**
     * Gets the stored user information from the session.
     *
     * @param SessionInterface $session The session to get the info from.
     * @return array<string, mixed>|null The user information or null if not found.
     */
    public function getUserInfo(SessionInterface $session): ?array;

    /**
     * Clears the stored user information from the session.
     *
     * @param SessionInterface $session The session to clear the info from.
     */
    public function clearUserInfo(SessionInterface $session): void;

    /**
     * Clears all authentication information from the session.
     *
     * @param SessionInterface $session The session to clear.
     */
    public function clearSession(SessionInterface $session): void;

    /**
     * Stores the redirect URL for after authentication.
     *
     * @param SessionInterface $session The session to store the URL in.
     * @param string $url The redirect URL to store.
     */
    public function storeRedirectUrl(SessionInterface $session, string $url): void;

    /**
     * Gets the stored redirect URL.
     *
     * @param SessionInterface $session The session to get the URL from.
     * @return string|null The redirect URL or null if not found.
     */
    public function getRedirectUrl(SessionInterface $session): ?string;

    /**
     * Clears the stored redirect URL.
     *
     * @param SessionInterface $session The session to clear the URL from.
     */
    public function clearRedirectUrl(SessionInterface $session): void;
}
