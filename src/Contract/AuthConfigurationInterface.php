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
 * Interface for authentication configuration.
 *
 * This interface defines the contract for authentication configuration objects
 * that provide access to various authentication settings.
 */
interface AuthConfigurationInterface
{
    /**
     * Gets the Keycloak server URL.
     *
     * @return string The Keycloak server URL.
     */
    public function getKeycloakUrl(): string;

    /**
     * Gets the Keycloak realm name.
     *
     * @return string The realm name.
     */
    public function getRealm(): string;

    /**
     * Gets the OAuth2 client ID.
     *
     * @return string The client ID.
     */
    public function getClientId(): string;

    /**
     * Gets the OAuth2 client secret.
     *
     * @return string The client secret.
     */
    public function getClientSecret(): string;

    /**
     * Gets the OAuth2 redirect URI.
     *
     * @return string The redirect URI.
     */
    public function getRedirectUri(): string;

    /**
     * Gets the OAuth2 scopes.
     *
     * @return array<string> The scopes.
     */
    public function getScopes(): array;

    /**
     * Gets the protected routes.
     *
     * @return array<string> The protected routes.
     */
    public function getProtectedRoutes(): array;

    /**
     * Gets the authentication callback route.
     *
     * @return string The callback route.
     */
    public function getCallbackRoute(): string;

    /**
     * Gets the logout route.
     *
     * @return string The logout route.
     */
    public function getLogoutRoute(): string;

    /**
     * Gets the session lifetime in seconds.
     *
     * @return int The session lifetime.
     */
    public function getSessionLifetime(): int;

    /**
     * Gets whether to use secure cookies.
     *
     * @return bool True if secure cookies should be used.
     */
    public function getSecureCookies(): bool;

    /**
     * Gets the HTTP client options.
     *
     * @return array<string, mixed> The HTTP client options.
     */
    public function getHttpClientOptions(): array;

    /**
     * Converts the configuration to an array.
     *
     * @return array<string, mixed> The configuration as an array.
     */
    public function toArray(): array;
}
