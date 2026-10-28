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

/**
 * Routing and session refresh settings for web authentication.
 *
 * Redirect destinations are resolved configuration values. A null refresh
 * interval delegates the refresh policy to the authentication provider.
 */
interface WebConfigurationInterface
{
    /**
     * Returns the login path exposed to templates and local login flows.
     *
     * @return string The login path.
     */
    public function getLoginPath(): string;

    /**
     * Returns the path identifying logout requests in the web channel.
     *
     * @return string The logout path.
     */
    public function getLogoutPath(): string;

    /**
     * Returns the default destination after login.
     *
     * A requested or previously stored destination can take precedence over
     * this value in the login flow.
     *
     * @return string The default login redirect destination.
     */
    public function getLoginRedirectPath(): string;

    /**
     * Returns the default destination after logout.
     *
     * A provider-specific logout URL can take precedence in the web channel.
     *
     * @return string The default logout redirect destination.
     */
    public function getLogoutRedirectPath(): string;

    /**
     * Returns the fallback redirect destination for unauthenticated requests.
     *
     * The web channel uses this destination when the login flow does not
     * supply a redirect response.
     *
     * @return string The fallback redirect destination.
     */
    public function getUnauthorizedRedirectPath(): string;

    /**
     * Returns the configured interval between session user refresh checks.
     *
     * Null delegates the refresh policy to the provider, which may use its
     * default interval or token expiration. It does not disable refresh checks.
     *
     * @return int|null The interval in seconds, or null for the provider's policy.
     */
    public function getRefreshInterval(): ?int;
}
