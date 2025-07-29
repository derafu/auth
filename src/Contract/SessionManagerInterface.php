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

/**
 * Interface for session management.
 *
 * This interface defines the contract for session management services that can
 * store and retrieve authentication information.
 */
interface SessionManagerInterface
{
    /**
     * Starts the session if not already started.
     *
     * @return void
     */
    public function start(): void;

    /**
     * Stores authentication information in the session.
     *
     * @param string $accessToken The access token.
     * @param string|null $refreshToken The refresh token.
     * @param int|null $expiresAt The expiration timestamp.
     * @return void
     */
    public function storeAuthInfo(
        string $accessToken,
        ?string $refreshToken = null,
        ?int $expiresAt = null
    ): void;

    /**
     * Stores user information in the session.
     *
     * @param array $userInfo The user information.
     * @return void
     */
    public function storeUserInfo(array $userInfo): void;

    /**
     * Stores the state parameter for CSRF protection.
     *
     * @param string $state The state parameter.
     * @return void
     */
    public function storeState(string $state): void;

    /**
     * Stores the redirect URL for after authentication.
     *
     * @param string $url The redirect URL.
     * @return void
     */
    public function storeRedirectUrl(string $url): void;

    /**
     * Gets the stored redirect URL.
     *
     * @return string The redirect URL.
     */
    public function getRedirectUrl(): string;

    /**
     * Checks if authentication information exists.
     *
     * @return bool True if auth info exists, false otherwise.
     */
    public function hasAuthInfo(): bool;

    /**
     * Checks if the stored token has expired.
     *
     * @return bool True if token has expired, false otherwise.
     */
    public function isTokenExpired(): bool;

    /**
     * Gets the stored access token.
     *
     * @return string|null The access token or null if not found.
     */
    public function getAccessToken(): ?string;

    /**
     * Gets the stored refresh token.
     *
     * @return string|null The refresh token or null if not found.
     */
    public function getRefreshToken(): ?string;

    /**
     * Gets the stored user information.
     *
     * @return array|null The user information or null if not found.
     */
    public function getUserInfo(): ?array;

    /**
     * Gets the stored state parameter.
     *
     * @return string|null The state parameter or null if not found.
     */
    public function getState(): ?string;

    /**
     * Clears the stored state parameter.
     *
     * @return void
     */
    public function clearState(): void;

    /**
     * Clears all authentication information from the session.
     *
     * @return void
     */
    public function clear(): void;
}
