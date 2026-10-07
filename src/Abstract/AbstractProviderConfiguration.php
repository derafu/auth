<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Abstract;

use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;

/**
 * Abstract provider configuration.
 *
 * This class provides a base implementation for all provider configurations.
 */
abstract class AbstractProviderConfiguration implements ConfigurationInterface
{
    /**
     * The protected paths.
     *
     * @var array
     */
    private array $protectedPaths = [];

    /**
     * The login path.
     *
     * Must match the login route in the routing configuration.
     *
     * @var string
     */
    private string $loginPath = '/auth/login';

    /**
     * The logout path.
     *
     * Must match the logout route in the routing configuration.
     *
     * @var string
     */
    private string $logoutPath = '/auth/logout';

    /**
     * The login redirect path.
     *
     * Where the user will be redirected after login.
     */
    private string $loginRedirectPath = '/';

    /**
     * The logout redirect path.
     *
     * Where the user will be redirected after logout.
     *
     * @var string
     */
    private string $logoutRedirectPath = '/';

    /**
     * The unauthorized redirect path.
     *
     * Where the user will be redirected if they are unauthorized.
     *
     * @var string
     */
    private string $unauthorizedRedirectPath = '/';

    /**
     * Whether the authentication is enabled.
     *
     * This is useful to disable the authentication for development purposes.
     *
     * @var bool
     */
    private bool $enabled = true;

    private ?int $refreshInterval = null;

    /**
     * Creates a new abstract provider configuration.
     *
     * This must be called by the child class constructor.
     *
     * @param array<string, mixed> $config The configuration array.
     */
    public function __construct(array $config)
    {
        // Protected paths.
        $protectedPaths = $config['protected_paths']
            ?? $this->protectedPaths
        ;
        $this->protectedPaths = [];
        foreach ($protectedPaths as $key => $value) {
            if (is_int($key)) {
                $path = $value;
                $roles = [];
            } else {
                $path = $key;
                $roles = is_array($value) ? $value : [$value];
            }
            $this->protectedPaths[$path] = $roles;
        }

        // Login and logout paths.
        $this->loginPath = $config['login_path']
            ?? $this->loginPath
        ;
        $this->logoutPath = $config['logout_path']
            ?? $this->logoutPath
        ;

        // Redirect paths.
        $this->loginRedirectPath = $config['login_redirect_path']
            ?? $this->loginRedirectPath
        ;
        $this->logoutRedirectPath = $config['logout_redirect_path']
            ?? $this->logoutRedirectPath
        ;
        $this->unauthorizedRedirectPath = $config['unauthorized_redirect_path']
            ?? $this->unauthorizedRedirectPath
        ;

        // Enabled.
        $this->enabled = $config['enabled']
            ?? $this->enabled
        ;

        // Every how many seconds the user of a session is asked to the provider
        // again (its roles, that it still exists). 0 or not given: the provider
        // decides (see `getRefreshInterval()`).
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
    public function get(string $key, mixed $default = null): mixed
    {
        return match ($key) {
            'protected_paths' => $this->getProtectedPaths(),
            'login_path' => $this->getLoginPath(),
            'logout_path' => $this->getLogoutPath(),
            'login_redirect_path' => $this->getLoginRedirectPath(),
            'logout_redirect_path' => $this->getLogoutRedirectPath(),
            'unauthorized_redirect_path' => $this->getUnauthorizedRedirectPath(),
            'enabled' => $this->isEnabled(),
            'refresh_interval' => $this->getRefreshInterval(),
            default => $default,
        };
    }

    /**
     * {@inheritDoc}
     */
    public function toArray(): array
    {
        return [
            'protected_paths' => $this->getProtectedPaths(),
            'login_path' => $this->getLoginPath(),
            'logout_path' => $this->getLogoutPath(),
            'login_redirect_path' => $this->getLoginRedirectPath(),
            'logout_redirect_path' => $this->getLogoutRedirectPath(),
            'unauthorized_redirect_path' => $this->getUnauthorizedRedirectPath(),
            'enabled' => $this->isEnabled(),
            'refresh_interval' => $this->getRefreshInterval(),
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function getProtectedPaths(): array
    {
        return $this->protectedPaths;
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
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * {@inheritDoc}
     */
    public function getRefreshInterval(): ?int
    {
        return $this->refreshInterval;
    }

    /**
     * {@inheritDoc}
     */
    public function allowedRoles(string $path): array
    {
        // If the authentication is not enabled, no role is needed.
        if (!$this->isEnabled()) {
            return [];
        }

        // Check if path is in protected paths.
        $protectedPaths = $this->getProtectedPaths();
        foreach ($protectedPaths as $protectedPath => $roles) {
            if (str_starts_with($path, $protectedPath)) { // Simple path match.
                return $roles;
            }
        }

        // If no protected path matches, no role is needed.
        return [];
    }

    /**
     * {@inheritDoc}
     */
    public function requiresAuth(string $path): bool
    {
        // If the authentication is not enabled, return false.
        if (!$this->isEnabled()) {
            return false;
        }

        // Check if path is in protected paths.
        $protectedPaths = $this->getProtectedPaths();
        foreach ($protectedPaths as $protectedPath => $roles) {
            if (str_starts_with($path, $protectedPath)) { // Simple path match.
                return true;
            }
        }

        // If no path is matched, no authentication is required.
        return false;
    }
}
