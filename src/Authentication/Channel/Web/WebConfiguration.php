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

use Derafu\Array\ArrayReader;
use Derafu\Auth\Contract\WebConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;

/**
 * Resolves web authentication settings from application and provider defaults.
 *
 * Application path values take precedence over provider defaults and built-in
 * paths. Null path values use the next available default. Refresh intervals
 * must be non-negative integers; zero and null delegate to the provider.
 */
class WebConfiguration implements WebConfigurationInterface
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
     * @param array<string, mixed> $defaults What the provider says for the paths
     * that `$config` does not give (`AuthProviderInterface::webDefaults()`): a
     * provider with a login page of the site sends the user there.
     * @throws ConfigurationException If the refresh interval is not valid.
     * @throws TranslatableInvalidArgumentException If an effective path is not a string.
     */
    public function __construct(array $config = [], array $defaults = [])
    {
        $paths = ArrayReader::fromArray([
            'login_path' => $config['login_path'] ?? $defaults['login_path'] ?? $this->loginPath,
            'logout_path' => $config['logout_path'] ?? $defaults['logout_path'] ?? $this->logoutPath,
            'login_redirect_path' => $config['login_redirect_path'] ?? $defaults['login_redirect_path'] ?? $this->loginRedirectPath,
            'logout_redirect_path' => $config['logout_redirect_path'] ?? $defaults['logout_redirect_path'] ?? $this->logoutRedirectPath,
            'unauthorized_redirect_path' => $config['unauthorized_redirect_path'] ?? $defaults['unauthorized_redirect_path'] ?? $this->unauthorizedRedirectPath,
        ]);
        $this->loginPath = $paths->getString('login_path', $this->loginPath);
        $this->logoutPath = $paths->getString('logout_path', $this->logoutPath);
        $this->loginRedirectPath = $paths->getString('login_redirect_path', $this->loginRedirectPath);
        $this->logoutRedirectPath = $paths->getString('logout_redirect_path', $this->logoutRedirectPath);
        $this->unauthorizedRedirectPath = $paths->getString('unauthorized_redirect_path', $this->unauthorizedRedirectPath);

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

    /**
     * {@inheritDoc}
     */
    public function getLoginPath(): string
    {
        return $this->loginPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getLogoutPath(): string
    {
        return $this->logoutPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getLoginRedirectPath(): string
    {
        return $this->loginRedirectPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getLogoutRedirectPath(): string
    {
        return $this->logoutRedirectPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getUnauthorizedRedirectPath(): string
    {
        return $this->unauthorizedRedirectPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getRefreshInterval(): ?int
    {
        return $this->refreshInterval;
    }
}
