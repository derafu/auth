<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Factory;

use Derafu\Auth\Configuration\AuthConfiguration;
use Derafu\Auth\Contract\AuthConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;

class AuthConfigurationFactory
{
    /**
     * Creates a new authentication configuration.
     *
     * @param array $config The configuration array.
     */
    public static function create(array $config = []): AuthConfigurationInterface
    {
        if ($config['enabled'] ?? true) {
            self::validate($config);
        }

        return new AuthConfiguration(
            $config['keycloak_url'] ?? '',
            $config['realm'] ?? 'master',
            $config['client_id'] ?? '',
            $config['client_secret'] ?? '',
            $config['redirect_uri'] ?? '',
            $config['scopes'] ?? ['openid', 'profile', 'email'],
            $config['protected_routes'] ?? ['/dashboard', '/profile', '/admin'],
            $config['callback_route'] ?? '/auth/callback',
            $config['logout_route'] ?? '/auth/logout',
            $config['session_lifetime'] ?? 3600,
            $config['secure_cookies'] ?? false,
            $config['http_client_options'] ?? [
                'timeout' => 30,
                'connect_timeout' => 30,
                'verify' => false,
            ],
        );
    }

    /**
     * Validates the configuration array.
     *
     * This method validates the following configuration keys:
     *
     *   - keycloak_url: The Keycloak URL.
     *   - client_id: The client ID.
     *   - client_secret: The client secret.
     *   - redirect_uri: The redirect URI.
     *
     * @throws ConfigurationException If any of the required keys are missing.
     *
     * @param array $config The configuration array.
     */
    private static function validate(array $config = [])
    {
        if (empty($config['keycloak_url'])) {
            throw new ConfigurationException('Keycloak URL is required.');
        }

        if (empty($config['client_id'])) {
            throw new ConfigurationException('Client ID is required.');
        }

        if (empty($config['client_secret'])) {
            throw new ConfigurationException('Client secret is required.');
        }

        if (empty($config['redirect_uri'])) {
            throw new ConfigurationException('Redirect URI is required.');
        }
    }
}
