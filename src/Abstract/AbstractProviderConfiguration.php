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
     * The login redirect route.
     *
     * Where the user will be redirected after login.
     */
    private string $loginRedirectRoute = '/';

    /**
     * The logout redirect route.
     *
     * Where the user will be redirected after logout.
     *
     * @var string
     */
    private string $logoutRedirectRoute = '/';

    /**
     * The unauthorized redirect route.
     *
     * Where the user will be redirected if they are unauthorized.
     *
     * @var string
     */
    private string $unauthorizedRedirectRoute = '/';

    /**
     * Whether the authentication is enabled.
     *
     * This is useful to disable the authentication for development purposes.
     *
     * @var bool
     */
    private bool $enabled = true;

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
        $this->loginRedirectRoute = $config['login_redirect_route']
            ?? $this->loginRedirectRoute
        ;
        $this->logoutRedirectRoute = $config['logout_redirect_route']
            ?? $this->logoutRedirectRoute
        ;
        $this->unauthorizedRedirectRoute = $config['unauthorized_redirect_route']
            ?? $this->unauthorizedRedirectRoute
        ;

        // Enabled.
        $this->enabled = $config['enabled']
            ?? $this->enabled
        ;
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
            'login_redirect_route' => $this->getLoginRedirectRoute(),
            'logout_redirect_route' => $this->getLogoutRedirectRoute(),
            'unauthorized_redirect_route' => $this->getUnauthorizedRedirectRoute(),
            'enabled' => $this->isEnabled(),
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
            'login_redirect_route' => $this->getLoginRedirectRoute(),
            'logout_redirect_route' => $this->getLogoutRedirectRoute(),
            'unauthorized_redirect_route' => $this->getUnauthorizedRedirectRoute(),
            'enabled' => $this->isEnabled(),
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
    public function getLoginRedirectRoute(): string
    {
        return $this->loginRedirectRoute;
    }

    /**
     * {@inheritDoc}
     */
    public function getLogoutRedirectRoute(): string
    {
        return $this->logoutRedirectRoute;
    }

    /**
     * {@inheritDoc}
     */
    public function getUnauthorizedRedirectRoute(): string
    {
        return $this->unauthorizedRedirectRoute;
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
    public function allowedRoles(string $path): array
    {
        // If the authentication is not enabled, return false.
        if (!$this->isEnabled()) {
            return [];
        }

        // Check if path is in protected paths.
        $protectedPaths = $this->getProtectedPaths();
        foreach ($protectedPaths as $route => $roles) {
            if (str_starts_with($path, $route)) { // Simple route match.
                return $roles;
            }
        }

        // If no route is matched, return all roles.
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
        foreach ($protectedPaths as $route => $roles) {
            if (str_starts_with($path, $route)) { // Simple route match.
                return true;
            }
        }

        // If no route is matched, no authentication is required.
        return false;
    }
}
