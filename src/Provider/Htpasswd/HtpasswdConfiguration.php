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

use Derafu\Auth\Abstract\AbstractProviderConfiguration;
use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration class for the authentication with an `.htpasswd` file.
 */
class HtpasswdConfiguration extends AbstractProviderConfiguration implements ConfigurationInterface
{
    private string $htpasswdPath = '';

    /**
     * Creates a new htpasswd configuration.
     *
     * @param array<string, mixed> $config The configuration array.
     */
    public function __construct(array $config)
    {
        parent::__construct($config);

        $this->htpasswdPath = (string) ($config['htpasswd_path'] ?? $this->htpasswdPath);
        if (!empty($config['project_dir'])) {
            $this->htpasswdPath = str_replace(
                '%kernel.project_dir%',
                $config['project_dir'],
                $this->htpasswdPath
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        if ($this->htpasswdPath === '') {
            throw new ConfigurationException('The path of the htpasswd file is required.');
        }
    }

    /**
     * {@inheritDoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $value = parent::get($key, $default);
        if ($value !== null) {
            return $value;
        }

        return match ($key) {
            'htpasswd_path' => $this->getHtpasswdPath(),
            default => $default,
        };
    }

    /**
     * {@inheritDoc}
     */
    public function toArray(): array
    {
        return array_merge(parent::toArray(), [
            'htpasswd_path' => $this->getHtpasswdPath(),
        ]);
    }

    /**
     * {@inheritDoc}
     *
     * The file has no token that expires, so it is read again every
     * `DEFAULT_REFRESH_INTERVAL` seconds unless the configuration says another
     * number.
     */
    public function getRefreshInterval(): int
    {
        return parent::getRefreshInterval() ?? self::DEFAULT_REFRESH_INTERVAL;
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
