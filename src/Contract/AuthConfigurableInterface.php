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
     * Gets the current authentication configuration.
     *
     * @return AuthConfigurationInterface The configuration.
     */
    public function getConfiguration(): AuthConfigurationInterface;
}
