<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use PDO;

/**
 * A real SQLite database with a table of users, their roles, and the role
 * tables that the default queries of the provider use.
 */
final class UsersDatabase
{
    private readonly string $file;

    /**
     * @param list<array{identity: string, password: string, roles: list<string>, hash?: string}> $users
     * The hash of the password is made with `password_hash()` unless one is given.
     * @param string $table The table of the users.
     * @param string $identity The column of the identity.
     * @param string $password The column of the password.
     */
    public function __construct(
        array $users = [['identity' => 'ana@example.com', 'password' => 'secret', 'roles' => ['admin']]],
        private readonly string $table = 'user',
        private readonly string $identity = 'email',
        private readonly string $password = 'password'
    ) {
        $this->file = tempnam(sys_get_temp_dir(), 'auth-users-') ?: '';

        $pdo = new PDO('sqlite:' . $this->file);
        $pdo->exec(sprintf(
            'CREATE TABLE %s (id INTEGER PRIMARY KEY, %s TEXT, %s TEXT, name TEXT)',
            $this->table,
            $this->identity,
            $this->password
        ));
        $pdo->exec('CREATE TABLE role (id INTEGER PRIMARY KEY, name TEXT)');
        $pdo->exec(sprintf('CREATE TABLE %s_role (user_id INTEGER, role_id INTEGER)', $this->table));

        $roleIds = [];
        foreach ($users as $index => $user) {
            $id = $index + 1;
            $pdo->prepare(sprintf(
                'INSERT INTO %s (id, %s, %s, name) VALUES (:id, :identity, :password, :name)',
                $this->table,
                $this->identity,
                $this->password
            ))->execute([
                'id' => $id,
                'identity' => $user['identity'],
                'password' => $user['hash'] ?? password_hash($user['password'], PASSWORD_DEFAULT),
                'name' => 'User ' . $id,
            ]);

            foreach ($user['roles'] as $role) {
                if (!isset($roleIds[$role])) {
                    $roleIds[$role] = count($roleIds) + 1;
                    $pdo->prepare('INSERT INTO role (id, name) VALUES (:id, :name)')
                        ->execute(['id' => $roleIds[$role], 'name' => $role]);
                }
                $pdo->prepare(sprintf('INSERT INTO %s_role (user_id, role_id) VALUES (:user, :role)', $this->table))
                    ->execute(['user' => $id, 'role' => $roleIds[$role]]);
            }
        }
    }

    /**
     * The configuration of the database provider for this database.
     *
     * @param array<string, mixed> $config What is added to the configuration.
     */
    public function config(array $config = []): DatabaseConfiguration
    {
        return new DatabaseConfiguration($config + [
            'database_url' => 'sqlite:' . $this->file,
            'user_repository' => [
                'table' => $this->table,
                'field' => ['identity' => $this->identity, 'password' => $this->password],
            ],
        ]);
    }

    /**
     * The hash of the password of a user, as it is in the database now.
     */
    public function hash(string $identity): string
    {
        $pdo = new PDO('sqlite:' . $this->file);
        $statement = $pdo->prepare(sprintf(
            'SELECT %s FROM %s WHERE %s = :identity',
            $this->password,
            $this->table,
            $this->identity
        ));
        $statement->execute(['identity' => $identity]);

        return (string) $statement->fetchColumn();
    }

    /**
     * The file of the database.
     */
    public function file(): string
    {
        return $this->file;
    }

    /**
     * Deletes the database.
     */
    public function remove(): void
    {
        if (is_file($this->file)) {
            unlink($this->file);
        }
    }
}
