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
     * @param list<array{identity: string, password: string, roles: list<string>, hash?: string, active?: bool}> $users
     * The hash of the password is made with `password_hash()` unless one is given.
     * @param string $table The table of the users.
     * @param string $identity The column of the identity.
     * @param string $password The column of the password.
     */
    public function __construct(
        array $users = [['identity' => 'ana@example.com', 'password' => 'secret', 'roles' => ['admin']]],
        private readonly string $table = 'user',
        private readonly string $identity = 'email',
        private readonly string $password = 'password',
        private readonly bool $withActiveColumn = true,
        private readonly string $active = 'active'
    ) {
        $this->file = tempnam(sys_get_temp_dir(), 'auth-users-') ?: '';

        $pdo = new PDO('sqlite:' . $this->file);
        $pdo->exec(sprintf(
            'CREATE TABLE %s (id INTEGER PRIMARY KEY, %s TEXT, %s TEXT, name TEXT%s)',
            $this->table,
            $this->identity,
            $this->password,
            $this->withActiveColumn ? ', ' . $this->active . ' INTEGER NOT NULL DEFAULT 1' : ''
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

            if ($this->withActiveColumn && ($user['active'] ?? true) === false) {
                $this->setActive($user['identity'], false);
            }
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
     * Gives the user exactly these roles (what an administrator does in the
     * database while the user has a session).
     *
     * @param list<string> $roles
     */
    public function setRoles(string $identity, array $roles): void
    {
        $pdo = new PDO('sqlite:' . $this->file);
        $id = $this->userId($pdo, $identity);

        $pdo->prepare(sprintf('DELETE FROM %s_role WHERE user_id = :user', $this->table))->execute(['user' => $id]);
        foreach ($roles as $role) {
            $statement = $pdo->prepare('SELECT id FROM role WHERE name = :name');
            $statement->execute(['name' => $role]);
            $roleId = $statement->fetchColumn();
            if ($roleId === false) {
                $pdo->prepare('INSERT INTO role (name) VALUES (:name)')->execute(['name' => $role]);
                $roleId = $pdo->lastInsertId();
            }
            $pdo->prepare(sprintf('INSERT INTO %s_role (user_id, role_id) VALUES (:user, :role)', $this->table))
                ->execute(['user' => $id, 'role' => $roleId]);
        }
    }

    /**
     * Makes the user active or inactive: a user that exists, with its password
     * and its roles, that the application does not want to let in.
     */
    public function setActive(string $identity, bool $active): void
    {
        $pdo = new PDO('sqlite:' . $this->file);
        $pdo->prepare(sprintf('UPDATE %s SET %s = :active WHERE %s = :identity', $this->table, $this->active, $this->identity))
            ->execute(['active' => $active ? 1 : 0, 'identity' => $identity]);
    }

    public function setName(string $identity, string $name): void
    {
        $pdo = new PDO('sqlite:' . $this->file);
        $pdo->prepare(sprintf('UPDATE %s SET name = :name WHERE %s = :identity', $this->table, $this->identity))
            ->execute(['name' => $name, 'identity' => $identity]);
    }

    /**
     * Deletes the user.
     */
    public function delete(string $identity): void
    {
        $pdo = new PDO('sqlite:' . $this->file);
        $id = $this->userId($pdo, $identity);

        $pdo->prepare(sprintf('DELETE FROM %s_role WHERE user_id = :user', $this->table))->execute(['user' => $id]);
        $pdo->prepare(sprintf('DELETE FROM %s WHERE id = :user', $this->table))->execute(['user' => $id]);
    }

    /**
     * Makes the table of the users fail (it is not there) as a database that has
     * a problem does, until `repair()`.
     */
    public function break(): void
    {
        (new PDO('sqlite:' . $this->file))->exec(sprintf('ALTER TABLE %s RENAME TO %s_broken', $this->table, $this->table));
    }

    public function repair(): void
    {
        (new PDO('sqlite:' . $this->file))->exec(sprintf('ALTER TABLE %s_broken RENAME TO %s', $this->table, $this->table));
    }

    private function userId(PDO $pdo, string $identity): int
    {
        $statement = $pdo->prepare(sprintf('SELECT id FROM %s WHERE %s = :identity', $this->table, $this->identity));
        $statement->execute(['identity' => $identity]);

        return (int) $statement->fetchColumn();
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
