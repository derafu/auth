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
 * Reads and validates the htpasswd and optional group-file paths.
 */
interface HtpasswdConfigurationInterface
{
    /**
     * Validates the settings required to authenticate against this backend.
     *
     * @throws ConfigurationException If the required backend location is not configured.
     */
    public function validate(): void;

    /**
     * Gets the path of the group file (`.htgroup`), which gives the roles of the
     * users, or an empty text if there is none: the users have no roles.
     *
     * @return string The path of the group file.
     */
    public function getGroupPath(): string;

    /**
     * Gets the path of the htpasswd file.
     *
     * @return string The path of the htpasswd file.
     */
    public function getHtpasswdPath(): string;
}
