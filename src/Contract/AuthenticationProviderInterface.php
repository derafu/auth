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
 * Interface for authentication providers.
 *
 * This interface defines the contract for authentication services that can
 * verify user credentials and provide user information.
 */
interface AuthenticationProviderInterface
{
    /**
     * Creates an authorization URL for the authentication flow.
     *
     * @param array $options Additional options for the authorization URL.
     * @return string The authorization URL.
     */
    public function createAuthorizationUrl(array $options = []): string;

    /**
     * Gets the state parameter for CSRF protection.
     *
     * @return string The state parameter.
     */
    public function getState(): string;

    /**
     * Exchanges an authorization code for an access token.
     *
     * @param string $code The authorization code.
     * @return array The token information.
     * @throws \Derafu\Auth\Exception\AuthenticationException.
     */
    public function exchangeCodeForToken(string $code): array;

    /**
     * Refreshes an access token using a refresh token.
     *
     * @param string $refreshToken The refresh token.
     * @return array The new token information.
     * @throws \Derafu\Auth\Exception\AuthenticationException.
     */
    public function refreshToken(string $refreshToken): array;

    /**
     * Gets user information using an access token.
     *
     * @param string $accessToken The access token.
     * @return array The user information.
     * @throws \Derafu\Auth\Exception\AuthenticationException.
     */
    public function getUserInfo(string $accessToken): array;

    /**
     * Validates if a token is still valid.
     *
     * @param string $accessToken The access token to validate.
     * @return bool True if the token is valid, false otherwise.
     */
    public function isTokenValid(string $accessToken): bool;
}
