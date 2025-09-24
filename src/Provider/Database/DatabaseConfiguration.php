<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Database;

use Derafu\Auth\Abstract\AbstractProviderConfiguration;
use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;

/**
 * Configuration class for Database authentication settings.
 */
class DatabaseConfiguration extends AbstractProviderConfiguration implements ConfigurationInterface
{
    /**
     * The default user identity field.
     *
     * @var string
     */
    private const DEFAULT_USER_IDENTITY_FIELD = 'username';

    /**
     * The default user password field.
     *
     * @var string
     */
    private const DEFAULT_USER_PASSWORD_FIELD = 'password';

    /**
     * The database URL.
     *
     * @var string
     */
    private string $databaseUrl = '';

    /**
     * The user repository configuration.
     *
     * This defines the configuration for the user repository. Mapping the
     * table and fields to use for the user repository.
     *
     * @var array
     */
    private array $userRepository = [];

    /**
     * Creates a new database configuration.
     *
     * @param array<string, mixed> $config The configuration array.
     */
    public function __construct(array $config)
    {
        parent::__construct($config);

        $this->databaseUrl = $config['database_url'] ?? $this->databaseUrl;
        if (!empty($config['project_dir'])) {
            $this->databaseUrl = str_replace(
                '%kernel.project_dir%',
                $config['project_dir'],
                $this->databaseUrl
            );
        }

        $this->userRepository = $this->createUserRepositoryConfig(
            $config['user_repository'] ?? []
        );
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        if (empty($this->databaseUrl)) {
            throw new ConfigurationException('Database URL is required.');
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
            'database_url' => $this->getDatabaseUrl(),
            'user_repository' => $this->getUserRepository(),
            default => $default,
        };
    }

    /**
     * {@inheritDoc}
     */
    public function toArray(): array
    {
        $array = parent::toArray();

        return array_merge($array, [
            'database_url' => $this->getDatabaseUrl(),
            'user_repository' => $this->getUserRepository(),
        ]);
    }

    /**
     * Gets the database URL.
     *
     * @return string The database URL.
     */
    public function getDatabaseUrl(): string
    {
        return $this->databaseUrl;
    }

    /**
     * Gets the user repository configuration.
     *
     * @return array The user repository configuration.
     */
    public function getUserRepository(): array
    {
        return $this->userRepository;
    }

    /**
     * Gets the user identity field.
     *
     * @return string The user identity field.
     */
    public function getUserIdentityField(): string
    {
        return $this->userRepository['field']['identity']
            ?? self::DEFAULT_USER_IDENTITY_FIELD
        ;
    }

    /**
     * Gets the user password field.
     *
     * @return string The user password field.
     */
    public function getUserPasswordField(): string
    {
        return $this->userRepository['field']['password']
            ?? self::DEFAULT_USER_PASSWORD_FIELD
        ;
    }

    /**
     * Creates the user repository configuration.
     *
     * @return array The user repository configuration.
     */
    private function createUserRepositoryConfig(array $config): array
    {
        return [
            'table' => $config['table'] ?? 'user',
            'field' => [
                'identity' => $config['field']['identity']
                    ?? self::DEFAULT_USER_IDENTITY_FIELD
                ,
                'password' => $config['field']['password']
                    ?? self::DEFAULT_USER_PASSWORD_FIELD
                ,
            ],
            'sql_get_roles' => $config['sql_get_roles']
                ?? 'SELECT role FROM user_role WHERE user_id = :identity'
            ,
            'sql_get_details' => $config['sql_get_details']
                ?? 'SELECT * FROM user WHERE id = :identity'
            ,
        ];
    }
}
