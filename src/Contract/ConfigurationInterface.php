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

use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration interface.
 *
 * Provides a consistent interface for all configuration classes across
 * different authentication and authorization providers.
 */
interface ConfigurationInterface
{
    /**
     * Validates the configuration.
     *
     * @throws ConfigurationException If configuration is invalid.
     */
    public function validate(): void;

    /**
     * Gets a specific configuration value.
     *
     * @param string $key The configuration key.
     * @param mixed $default The default value if key doesn't exist.
     * @return mixed The configuration value.
     */
    public function get(string $key, mixed $default = null): mixed;

    /**
     * Gets the configuration as an array.
     *
     * @return array<string, mixed> The configuration data.
     */
    public function toArray(): array;
}
