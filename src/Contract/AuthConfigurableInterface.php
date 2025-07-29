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

/**
 * Interface for configurable authentication components.
 *
 * This interface defines the contract for authentication components that can be
 * configured with authentication settings.
 */
interface AuthConfigurableInterface
{
    /**
     * Sets the authentication configuration.
     *
     * @param array $configuration The configuration array.
     * @return static
     */
    public function setConfiguration(array $configuration): static;

    /**
     * Gets the current authentication configuration.
     *
     * @return AuthConfigurationInterface The configuration.
     */
    public function getConfiguration(): AuthConfigurationInterface;

    /**
     * Resolves and validates the configuration.
     *
     * @param array $configuration The raw configuration array.
     * @return AuthConfigurationInterface The resolved and validated configuration.
     */
    public function resolveConfiguration(array $configuration): AuthConfigurationInterface;

    /**
     * Gets the configuration schema for validation.
     *
     * @return array<string,array<string,mixed>> The configuration schema.
     */
    public function getConfigurationSchema(): array;
}
