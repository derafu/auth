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

use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\UserRepositoryInterface;
use Derafu\Auth\User;
use PDO;
use PDOStatement;

/**
 * Database user repository implementation.
 *
 * It authenticates a user against a table of a database: the hash of the
 * password is verified with `password_verify()`, the roles and the details of
 * the user come from the queries of the configuration (`sql_get_roles` and
 * `sql_get_details`, with the parameter `:identity`), and:
 *
 *   - A user that does not exist takes as long as one that does (the password is
 *     verified against a hash anyway), so the time it takes does not say which
 *     identities exist.
 *   - The hash of a password that was made with an algorithm or a cost that is
 *     not the current one (`PASSWORD_DEFAULT`) is made again when the user logs
 *     in, which is the only time that the password is known.
 *   - The column of the password is never kept in the user: the user goes to the
 *     session.
 *
 * The connection is made when it is needed, from the URL of the configuration,
 * unless a `PDO` is given.
 */
class DatabaseUserRepository implements UserRepositoryInterface
{
    /**
     * The hash that is verified when the user does not exist.
     */
    private static ?string $unknownUserHash = null;

    private ?PDO $pdo;

    /**
     * Creates a new Database user repository.
     *
     * @param DatabaseConfiguration $config The Database configuration.
     * @param PDO|null $pdo The connection to the database. By default, one made
     * from the URL of the configuration when it is needed.
     */
    public function __construct(
        private readonly DatabaseConfiguration $config,
        ?PDO $pdo = null
    ) {
        $this->pdo = $pdo;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(string $credential, ?string $password = null): ?UserInterface
    {
        $repository = $this->config->getUserRepository();
        $passwordField = $this->config->getUserPasswordField();

        $statement = $this->query(sprintf(
            'SELECT %s FROM %s WHERE %s = :identity',
            $passwordField,
            $repository['table'],
            $this->config->getUserIdentityField()
        ), $credential);
        $hash = $statement->fetchColumn();

        // The same work for a user that does not exist.
        if ($hash === false || $hash === null) {
            password_verify($password ?? '', self::unknownUserHash());

            return null;
        }

        $hash = (string) $hash;
        if ($password === null || !password_verify($password, $hash)) {
            return null;
        }

        if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
            $this->rehash($credential, $password);
        }

        // The details are what the query gives, without the password.
        $details = $this->query((string) $repository['sql_get_details'], $credential)->fetch(PDO::FETCH_ASSOC);
        $details = is_array($details) ? $details : [];
        unset($details[$passwordField]);

        $roles = [];
        foreach ($this->query((string) $repository['sql_get_roles'], $credential)->fetchAll(PDO::FETCH_NUM) as $role) {
            $roles[] = (string) $role[0];
        }

        return new User($credential, $roles, $details);
    }

    /**
     * Makes the hash of the password again with the current algorithm.
     */
    private function rehash(string $identity, string $password): void
    {
        $repository = $this->config->getUserRepository();

        $statement = $this->pdo()->prepare(sprintf(
            'UPDATE %s SET %s = :hash WHERE %s = :identity',
            $repository['table'],
            $this->config->getUserPasswordField(),
            $this->config->getUserIdentityField()
        ));
        $statement->execute(['hash' => password_hash($password, PASSWORD_DEFAULT), 'identity' => $identity]);
    }

    /**
     * Runs a query of the configuration for an identity.
     */
    private function query(string $sql, string $identity): PDOStatement
    {
        $statement = $this->pdo()->prepare($sql);
        $statement->execute(['identity' => $identity]);

        return $statement;
    }

    /**
     * The connection to the database.
     */
    private function pdo(): PDO
    {
        return $this->pdo ??= new PDO($this->config->getDatabaseUrl());
    }

    /**
     * The hash of a password that no user has, to verify when the user does not
     * exist: made once, with the current algorithm.
     */
    private static function unknownUserHash(): string
    {
        return self::$unknownUserHash ??= password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
    }
}
