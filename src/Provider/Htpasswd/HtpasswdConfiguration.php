<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Htpasswd;

use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration class for the authentication with an `.htpasswd` file.
 */
class HtpasswdConfiguration
{
    private string $htpasswdPath = '';

    private string $groupPath = '';

    /**
     * Creates a new htpasswd configuration.
     *
     * @param array<string, mixed> $config The configuration array.
     */
    public function __construct(array $config)
    {
        $this->htpasswdPath = (string) ($config['htpasswd_path'] ?? $this->htpasswdPath);
        $this->groupPath = (string) ($config['group_path'] ?? $this->groupPath);
        if (!empty($config['project_dir'])) {
            $this->htpasswdPath = str_replace(
                '%kernel.project_dir%',
                $config['project_dir'],
                $this->htpasswdPath
            );
            $this->groupPath = str_replace(
                '%kernel.project_dir%',
                $config['project_dir'],
                $this->groupPath
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        if ($this->htpasswdPath === '') {
            throw new ConfigurationException('The path of the htpasswd file is not configured: set AUTH_HTPASSWD_PATH.');
        }
    }

    /**
     * Gets the path of the group file (`.htgroup`), which gives the roles of the
     * users, or an empty text if there is none: the users have no roles.
     *
     * @return string The path of the group file.
     */
    public function getGroupPath(): string
    {
        return $this->groupPath;
    }

    /**
     * Gets the path of the htpasswd file.
     *
     * @return string The path of the htpasswd file.
     */
    public function getHtpasswdPath(): string
    {
        return $this->htpasswdPath;
    }
}
