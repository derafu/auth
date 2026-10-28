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

/**
 * Reads and validates database authentication settings without requiring a
 * particular configuration source.
 */
interface DatabaseConfigurationInterface
{
    /**
     * Validates the settings required to authenticate against this backend.
     *
     * @throws ConfigurationException If the required backend location is not configured.
     */
    public function validate(): void;

    /**
     * Gets the database URL.
     *
     * @return string The database URL.
     */
    public function getDatabaseUrl(): string;

    /**
     * Gets the user repository configuration.
     *
     * @return array{
     *     table: string,
     *     field: array{identity: string, password: string, active: string},
     *     sql_get_roles: string,
     *     sql_get_details: string,
     *     sql_is_active: string|null
     * } The user repository configuration.
     */
    public function getUserRepository(): array;

    /**
     * Gets the user identity field.
     *
     * @return string The user identity field.
     */
    public function getUserIdentityField(): string;

    /**
     * Gets the user password field.
     *
     * @return string The user password field.
     */
    public function getUserPasswordField(): string;
}
