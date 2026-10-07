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
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\User;
use PDO;
use PDOException;
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

        // The password is right, but a user that is not active is not let in. It
        // is the same answer as a wrong password, and its hash is not touched.
        if (!$this->isActive($credential)) {
            return null;
        }

        if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
            $this->rehash($credential, $password);
        }

        return $this->userOf($credential);
    }

    /**
     * Finds a user by its identity, with its roles and details as the database
     * has them now.
     *
     * It is what a session does to know whether its user is still the same: the
     * password is not asked (the user already logged in), and it is not read nor
     * changed.
     *
     * @param string $identity The identity of the user.
     * @return UserInterface|null The user, or null if there is no user with that
     * identity (it was deleted).
     * @throws PDOException If the database can not be asked.
     */
    public function find(string $identity): ?UserInterface
    {
        $repository = $this->config->getUserRepository();

        $statement = $this->query(sprintf(
            'SELECT %s FROM %s WHERE %s = :identity',
            $this->config->getUserPasswordField(),
            $repository['table'],
            $this->config->getUserIdentityField()
        ), $identity);

        if ($statement->fetch(PDO::FETCH_NUM) === false || !$this->isActive($identity)) {
            return null;
        }

        return $this->userOf($identity);
    }

    /**
     * Tells whether the user is active, with the query of the configuration
     * (`sql_is_active`): the first value that it gives, and no row is not active.
     * `0`, `false`, `null`, an empty text and the texts `0`, `f`, `false`, `n`,
     * `no` and `off` say that it is not; anything else says that it is (a count
     * of two, for example).
     *
     * @param string $identity The identity of the user.
     * @return bool True if the user is active, or if the configuration has no
     * query (the check is off).
     * @throws ConfigurationException If the query fails: it is the one of the
     * configuration that is wrong (the table has no such column), not the
     * database.
     */
    private function isActive(string $identity): bool
    {
        $sql = $this->config->getUserRepository()['sql_is_active'];
        if ($sql === null) {
            return true;
        }

        try {
            $value = $this->query((string) $sql, $identity)->fetchColumn();
        } catch (PDOException $e) {
            throw new ConfigurationException(
                [
                    'The query "sql_is_active" failed: {error}. If the table has no column "{column}", give your own query in "sql_is_active" or turn the check off with false.',
                    'error' => $e->getMessage(),
                    'column' => $this->config->getUserRepository()['field']['active'],
                ],
                0,
                $e
            );
        }

        if ($value === false || $value === null) {
            return false;
        }

        $text = strtolower(trim((string) $value));

        return !in_array($text, ['', 'f', 'false', 'n', 'no', 'off'], true)
            && !(is_numeric($text) && (float) $text === 0.0)
        ;
    }

    /**
     * The user with this identity, with the roles and the details that the
     * queries of the configuration give.
     */
    private function userOf(string $identity): User
    {
        $repository = $this->config->getUserRepository();

        // The details are what the query gives, without the password.
        $details = $this->query((string) $repository['sql_get_details'], $identity)->fetch(PDO::FETCH_ASSOC);
        $details = is_array($details) ? $details : [];
        unset($details[$this->config->getUserPasswordField()]);

        $roles = [];
        foreach ($this->query((string) $repository['sql_get_roles'], $identity)->fetchAll(PDO::FETCH_NUM) as $role) {
            $roles[] = (string) $role[0];
        }

        return new User($identity, $roles, $details);
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
        // The identity goes in `:identity`; a query that does not use it (one
        // that does not depend on the user) is run as it is.
        $statement->execute(str_contains($sql, ':identity') ? ['identity' => $identity] : []);

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
