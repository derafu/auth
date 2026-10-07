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
     * {@inheritDoc}
     *
     * The database has no token that expires, so it asks again every
     * `DEFAULT_REFRESH_INTERVAL` seconds unless the configuration says another
     * number.
     */
    public function getRefreshInterval(): int
    {
        return parent::getRefreshInterval() ?? self::DEFAULT_REFRESH_INTERVAL;
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
     * @return array The user repository configuration.
     */
    private function createUserRepositoryConfig(array $config): array
    {
        $userRepositoryConfig = [
            'table' => $config['table'] ?? 'user',
            'field' => [
                'identity' => $config['field']['identity'] ?? 'email',
                'password' => $config['field']['password'] ?? 'password',
                'active' => $config['field']['active'] ?? 'active',
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
            if (!is_string($name) || !preg_match('/^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/', $name)) {
                throw new ConfigurationException([
                    'The name "{name}" is not valid for a table or a column.',
                    'name' => is_string($name) ? $name : get_debug_type($name),
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
        $userRepositoryConfig['sql_get_roles'] = $config['sql_get_roles']
            ?? sprintf(
                $sqlGetRoles,
                $userRepositoryConfig['table'],
                $userRepositoryConfig['table'],
                $userRepositoryConfig['field']['identity']
            )
        ;

        $userRepositoryConfig['sql_get_details'] = $config['sql_get_details']
            ?? sprintf(
                'SELECT * FROM %s WHERE %s = :identity',
                $userRepositoryConfig['table'],
                $userRepositoryConfig['field']['identity']
            )
        ;

        // The query that tells whether a user is active (a user can exist, with
        // its password and its roles, and not be let in): the first value that it
        // gives says it. `false` (or the text `false`, which is what an
        // environment variable can say) is for who does not have the concept: the
        // check is off and every user that exists is active.
        $sqlIsActive = $config['sql_is_active'] ?? null;
        if ($sqlIsActive === false || (is_string($sqlIsActive) && strtolower(trim($sqlIsActive)) === 'false')) {
            $userRepositoryConfig['sql_is_active'] = null;
        } else {
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
