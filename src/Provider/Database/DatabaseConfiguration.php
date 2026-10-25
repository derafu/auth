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

use Derafu\Array\ArrayReader;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;

/**
 * Configuration class for Database authentication settings.
 */
class DatabaseConfiguration
{
    private string $databaseUrl = '';

    /**
     * The user repository configuration.
     *
     * This defines the configuration for the user repository. Mapping the
     * table and fields to use for the user repository.
     *
     * @var array{
     *     table: string,
     *     field: array{identity: string, password: string, active: string},
     *     sql_get_roles: string,
     *     sql_get_details: string,
     *     sql_is_active: string|null
     * }
     */
    private array $userRepository;

    /**
     * Creates a new database configuration.
     *
     * @param array<string, mixed> $config The configuration array.
     * @throws TranslatableInvalidArgumentException If a configuration value has an invalid type.
     */
    public function __construct(array $config)
    {
        $reader = ArrayReader::fromArray($config);
        $this->databaseUrl = $reader->getString('database_url', $this->databaseUrl);
        $projectDir = $reader->getString('project_dir', '');
        if (!empty($projectDir)) {
            $this->databaseUrl = str_replace(
                '%kernel.project_dir%',
                $projectDir,
                $this->databaseUrl
            );
        }

        $this->userRepository = $this->createUserRepositoryConfig(
            $reader->getArray('user_repository') ?? []
        );
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        if (empty($this->databaseUrl)) {
            throw new ConfigurationException('The database URL is not configured: set AUTH_DATABASE_URL (or DATABASE_URL).');
        }
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
     * @return array{
     *     table: string,
     *     field: array{identity: string, password: string, active: string},
     *     sql_get_roles: string,
     *     sql_get_details: string,
     *     sql_is_active: string|null
     * } The user repository configuration.
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
        return $this->userRepository['field']['identity'];
    }

    /**
     * Gets the user password field.
     *
     * @return string The user password field.
     */
    public function getUserPasswordField(): string
    {
        return $this->userRepository['field']['password'];
    }

    /**
     * Creates the user repository configuration.
     *
     * @param array<array-key, mixed> $config The repository configuration.
     * @return array{
     *     table: string,
     *     field: array{identity: string, password: string, active: string},
     *     sql_get_roles: string,
     *     sql_get_details: string,
     *     sql_is_active: string|null
     * } The user repository configuration.
     */
    private function createUserRepositoryConfig(array $config): array
    {
        $reader = ArrayReader::fromArray($config);
        $fields = ArrayReader::fromArray($reader->getArray('field') ?? []);
        $userRepositoryConfig = [
            'table' => $reader->getString('table', 'user'),
            'field' => [
                'identity' => $fields->getString('identity', 'email'),
                'password' => $fields->getString('password', 'password'),
                'active' => $fields->getString('active', 'active'),
            ],
        ];

        // They are put in the queries as they are: only names are valid (a table,
        // or a table of a schema, and columns).
        foreach ([
            $userRepositoryConfig['table'],
            $userRepositoryConfig['field']['identity'],
            $userRepositoryConfig['field']['password'],
            $userRepositoryConfig['field']['active'],
        ] as $name) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/', $name)) {
                throw new ConfigurationException([
                    'The name "{name}" is not valid for a table or a column.',
                    'name' => $name,
                ]);
            }
        }

        $sqlGetRoles = '
            SELECT r.name
            FROM
                role as r
                JOIN %s_role as ur ON r.id = ur.role_id
                JOIN %s AS u ON ur.user_id = u.id
            WHERE u.%s = :identity
        ';
        $userRepositoryConfig['sql_get_roles'] = $reader->getString(
            'sql_get_roles',
            sprintf(
                $sqlGetRoles,
                $userRepositoryConfig['table'],
                $userRepositoryConfig['table'],
                $userRepositoryConfig['field']['identity']
            )
        );

        $userRepositoryConfig['sql_get_details'] = $reader->getString(
            'sql_get_details',
            sprintf(
                'SELECT * FROM %s WHERE %s = :identity',
                $userRepositoryConfig['table'],
                $userRepositoryConfig['field']['identity']
            )
        );

        // The query that tells whether a user is active (a user can exist, with
        // its password and its roles, and not be let in): the first value that it
        // gives says it. `false` (or the text `false`, which is what an
        // environment variable can say) is for who does not have the concept: the
        // check is off and every user that exists is active.
        $sqlIsActive = $config['sql_is_active'] ?? null;
        if ($sqlIsActive === false || (is_string($sqlIsActive) && strtolower(trim($sqlIsActive)) === 'false')) {
            $userRepositoryConfig['sql_is_active'] = null;
        } else {
            $sqlIsActive = $reader->getString('sql_is_active');
            $userRepositoryConfig['sql_is_active'] = $sqlIsActive === null || $sqlIsActive === ''
                ? sprintf(
                    'SELECT %s FROM %s WHERE %s = :identity',
                    $userRepositoryConfig['field']['active'],
                    $userRepositoryConfig['table'],
                    $userRepositoryConfig['field']['identity']
                )
                : $sqlIsActive
            ;
        }

        return $userRepositoryConfig;
    }
}
