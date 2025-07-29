<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Validator;

use Derafu\Auth\Contract\AuthConfigurationInterface;
use Derafu\Auth\Contract\RouteValidatorInterface;

/**
 * Route validator implementation.
 *
 * This validator determines which routes require authentication based on the
 * configuration.
 */
class RouteValidator implements RouteValidatorInterface
{
    /**
     * Creates a new route validator.
     *
     * @param AuthConfigurationInterface $config The authentication configuration.
     */
    public function __construct(
        private readonly AuthConfigurationInterface $config
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function requiresAuth(string $path): bool
    {
        foreach ($this->config->getProtectedRoutes() as $route) {
            if (str_starts_with($path, $route)) {
                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function isCallbackPath(string $path): bool
    {
        return $path === $this->config->getCallbackRoute();
    }

    /**
     * {@inheritDoc}
     */
    public function isLogoutPath(string $path): bool
    {
        return $path === $this->config->getLogoutRoute();
    }

    /**
     * {@inheritDoc}
     */
    public function getProtectedRoutes(): array
    {
        return $this->config->getProtectedRoutes();
    }

    /**
     * {@inheritDoc}
     */
    public function getCallbackRoute(): string
    {
        return $this->config->getCallbackRoute();
    }

    /**
     * {@inheritDoc}
     */
    public function getLogoutRoute(): string
    {
        return $this->config->getLogoutRoute();
    }
}
