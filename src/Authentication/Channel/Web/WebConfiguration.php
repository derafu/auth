<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication\Channel\Web;

use Derafu\Auth\Exception\ConfigurationException;

/**
 * The configuration of the web channel: the session of a user, and where it is
 * sent in and out.
 *
 * Nothing here is about a provider: the paths, and every how many seconds the
 * user of a session is asked to its provider again.
 */
class WebConfiguration
{
    /**
     * Every how many seconds, by default, the user of a session is asked to its
     * provider again (when the provider has nothing better, like the expiration of
     * a token).
     */
    public const DEFAULT_REFRESH_INTERVAL = 300;

    /**
     * The login path: must match the login route.
     */
    private string $loginPath = '/auth/login';

    /**
     * The logout path: must match the logout route.
     */
    private string $logoutPath = '/auth/logout';

    /**
     * Where the user is sent after the login when no page was requested before.
     */
    private string $loginRedirectPath = '/';

    /**
     * Where the user is sent after the logout.
     */
    private string $logoutRedirectPath = '/';

    /**
     * Where the user is sent when it is not authenticated and the login is not a
     * page of the provider.
     */
    private string $unauthorizedRedirectPath = '/';

    private ?int $refreshInterval = null;

    /**
     * Creates the configuration.
     *
     * @param array<string, mixed> $config `login_path`, `logout_path`,
     * `login_redirect_path`, `logout_redirect_path`, `unauthorized_redirect_path`
     * and `refresh_interval` (seconds, 0 or not given: the provider decides).
     * @throws ConfigurationException If the refresh interval is not valid.
     */
    public function __construct(array $config = [])
    {
        $this->loginPath = $config['login_path'] ?? $this->loginPath;
        $this->logoutPath = $config['logout_path'] ?? $this->logoutPath;
        $this->loginRedirectPath = $config['login_redirect_path'] ?? $this->loginRedirectPath;
        $this->logoutRedirectPath = $config['logout_redirect_path'] ?? $this->logoutRedirectPath;
        $this->unauthorizedRedirectPath = $config['unauthorized_redirect_path'] ?? $this->unauthorizedRedirectPath;

        // Every how many seconds the user of a session is asked to the provider
        // again (its roles, that it still exists). 0 or not given: the provider
        // decides.
        $refreshInterval = $config['refresh_interval'] ?? null;
        if ($refreshInterval !== null && (!is_int($refreshInterval) || $refreshInterval < 0)) {
            throw new ConfigurationException(
                'The refresh interval must be a number of seconds, 0 or more.'
            );
        }
        $this->refreshInterval = $refreshInterval === 0 ? null : $refreshInterval;
    }

    public function getLoginPath(): string
    {
        return $this->loginPath;
    }

    public function getLogoutPath(): string
    {
        return $this->logoutPath;
    }

    public function getLoginRedirectPath(): string
    {
        return $this->loginRedirectPath;
    }

    public function getLogoutRedirectPath(): string
    {
        return $this->logoutRedirectPath;
    }

    public function getUnauthorizedRedirectPath(): string
    {
        return $this->unauthorizedRedirectPath;
    }

    /**
     * The seconds between two times that the session asks the provider again, or
     * null if the configuration does not say (the provider decides).
     */
    public function getRefreshInterval(): ?int
    {
        return $this->refreshInterval;
    }
}
