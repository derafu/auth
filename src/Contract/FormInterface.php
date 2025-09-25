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
 * Form interface.
 *
 * Provides a consistent interface for all form classes across different
 * authentication and authorization providers.
 */
interface FormInterface
{
    /**
     * Gets the form definition.
     *
     * @return array The form definition.
     */
    public function getDefinition(): array;
}
