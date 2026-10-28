<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;

/**
 * Selects the application's authentication provider and exposes its services.
 *
 * Provider selection is deferred until a provider-dependent service is requested.
 * Web configuration remains available without a usable provider so public pages
 * can expose authentication links before authentication is configured.
 */
interface AuthProviderRegistryInterface
{
    /**
     * Returns the provider selected by the application's configuration.
     *
     * @return AuthProviderInterface The selected authentication provider.
     * @throws ConfigurationException If no providers are registered, no provider
     * is selected, the selected name is unknown or its service has an invalid type.
     */
    public function provider(): AuthProviderInterface;

    /**
     * Returns the selected provider's web authentication flow.
     *
     * @return WebFlowInterface The selected web flow.
     * @throws ConfigurationException If provider selection or configuration fails.
     */
    public function webFlow(): WebFlowInterface;

    /**
     * Returns the selected provider's session manager.
     *
     * @return SessionManagerInterface The selected session manager.
     * @throws ConfigurationException If provider selection or configuration fails.
     */
    public function sessionManager(): SessionManagerInterface;

    /**
     * Returns the selected provider's API authentication scheme.
     *
     * @return ApiSchemeInterface The selected API scheme.
     * @throws ConfigurationException If provider selection or configuration fails.
     */
    public function apiScheme(): ApiSchemeInterface;

    /**
     * Returns the selected provider's account services.
     *
     * @return AccountInterface The selected account services.
     * @throws ConfigurationException If provider selection or configuration fails.
     */
    public function account(): AccountInterface;

    /**
     * Resolves web settings from application values and provider defaults.
     *
     * Application path values take precedence over provider defaults; null path
     * values use the next available default. If obtaining provider defaults
     * throws ConfigurationException, built-in defaults are used instead.
     *
     * @param array<string, mixed> $config Unvalidated web settings: login_path,
     * logout_path, login_redirect_path, logout_redirect_path,
     * unauthorized_redirect_path and refresh_interval. The interval is in seconds;
     * zero and null delegate refresh policy to the provider.
     * @return WebConfigurationInterface The resolved web configuration.
     * @throws ConfigurationException If the configured refresh interval is invalid.
     * @throws TranslatableInvalidArgumentException If an effective path has an invalid type.
     */
    public function webConfiguration(array $config): WebConfigurationInterface;
}
