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

use Derafu\Array\ArrayReader;
use Derafu\Auth\Contract\HtpasswdConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;

/**
 * Configuration class for the authentication with an `.htpasswd` file.
 */
class HtpasswdConfiguration implements HtpasswdConfigurationInterface
{
    private string $htpasswdPath = '';

    private string $groupPath = '';

    /**
     * Creates a new htpasswd configuration.
     *
     * @param array<string, mixed> $config The configuration array.
     * @throws TranslatableInvalidArgumentException If a configured path is not a string.
     */
    public function __construct(array $config)
    {
        $reader = ArrayReader::fromArray($config);
        $this->htpasswdPath = $reader->getString('htpasswd_path', $this->htpasswdPath);
        $this->groupPath = $reader->getString('group_path', $this->groupPath);
        $projectDir = $reader->getString('project_dir', '');
        if (!empty($projectDir)) {
            $this->htpasswdPath = str_replace(
                '%kernel.project_dir%',
                $projectDir,
                $this->htpasswdPath
            );
            $this->groupPath = str_replace(
                '%kernel.project_dir%',
                $projectDir,
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
     * {@inheritDoc}
     */
    public function getGroupPath(): string
    {
        return $this->groupPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getHtpasswdPath(): string
    {
        return $this->htpasswdPath;
    }
}
