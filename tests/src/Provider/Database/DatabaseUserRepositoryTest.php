<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Database;

use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\User;
use Derafu\Auth\UserFactory;
use Derafu\TestsAuth\Fixture\UsersDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The users are authenticated against a real database: the password is verified
 * with `password_verify()`, and the roles and the details come from the queries
 * of the configuration.
 */
#[CoversClass(DatabaseUserRepository::class)]
#[UsesClass(DatabaseConfiguration::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(User::class)]
#[UsesClass(UserFactory::class)]
final class DatabaseUserRepositoryTest extends TestCase
{
    private ?UsersDatabase $database = null;

    protected function tearDown(): void
    {
        $this->database?->remove();
        $this->database = null;
    }

    /**
     * @param list<array{identity: string, password: string, roles: list<string>}>|null $users
     */
    private function repository(?array $users = null, array $config = []): DatabaseUserRepository
    {
        $this->database = $users === null ? new UsersDatabase() : new UsersDatabase($users);

        return new DatabaseUserRepository($this->database->config($config));
    }

    #[Test]
    public function authenticatesAUserWithItsRoles(): void
    {
        $repository = $this->repository([
            ['identity' => 'ana@example.com', 'password' => 'secret', 'roles' => ['admin', 'editor']],
        ]);

        $user = $repository->authenticate('ana@example.com', 'secret');

        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('ana@example.com', $user->getIdentity());
        $this->assertSame(['admin', 'editor'], $user->getRoles());
        $this->assertFalse($user->isAnonymous());
    }

    #[Test]
    public function aUserWithoutRolesHasNone(): void
    {
        $user = $this->repository([['identity' => 'ana@example.com', 'password' => 'secret', 'roles' => []]])
            ->authenticate('ana@example.com', 'secret');

        $this->assertNotNull($user);
        $this->assertSame([], $user->getRoles());
    }

    #[Test]
    public function aWrongPasswordIsNotAuthenticated(): void
    {
        $this->assertNull($this->repository()->authenticate('ana@example.com', 'wrong'));
    }

    #[Test]
    public function anUnknownIdentityIsNotAuthenticated(): void
    {
        $this->assertNull($this->repository()->authenticate('nobody@example.com', 'secret'));
    }

    #[Test]
    public function aMissingPasswordIsNotAuthenticated(): void
    {
        $this->assertNull($this->repository()->authenticate('ana@example.com'));
    }

    #[Test]
    public function theUsersAreTheOnesOfTheirOwnIdentity(): void
    {
        $repository = $this->repository([
            ['identity' => 'ana@example.com', 'password' => 'one', 'roles' => ['admin']],
            ['identity' => 'ben@example.com', 'password' => 'two', 'roles' => ['editor']],
        ]);

        $this->assertSame(['editor'], $repository->authenticate('ben@example.com', 'two')?->getRoles());
        $this->assertNull($repository->authenticate('ben@example.com', 'one'));
    }

    #[Test]
    public function theTableAndTheFieldsAreTheOnesOfTheConfiguration(): void
    {
        $this->database = new UsersDatabase(
            [['identity' => '11111111-1', 'password' => 'clave', 'roles' => ['admin']]],
            table: 'people',
            identity: 'rut',
            password: 'secret'
        );
        $repository = new DatabaseUserRepository($this->database->config());

        $user = $repository->authenticate('11111111-1', 'clave');

        $this->assertNotNull($user);
        $this->assertSame('11111111-1', $user->getIdentity());
        $this->assertSame(['admin'], $user->getRoles());
    }

    #[Test]
    public function theDetailsComeFromTheQueryOfTheConfiguration(): void
    {
        $repository = $this->repository(config: [
            'user_repository' => [
                'table' => 'user',
                'field' => ['identity' => 'email', 'password' => 'password'],
                'sql_get_details' => 'SELECT id, name FROM user WHERE email = :identity',
            ],
        ]);

        $user = $repository->authenticate('ana@example.com', 'secret');

        $this->assertNotNull($user);
        $this->assertSame(['id' => 1, 'name' => 'User 1'], $user->getDetails());
        $this->assertSame('User 1', $user->getDetail('name'));
    }

    #[Test]
    public function theHashOfThePasswordIsNeverInTheDetails(): void
    {
        // The default query is `SELECT *`: the password is a column of it.
        $default = $this->repository()->authenticate('ana@example.com', 'secret');
        $this->assertNotNull($default);
        $this->assertSame(['id', 'email', 'name'], array_keys($default->getDetails()));

        // And a query that asks for it does not keep it either.
        $asked = $this->repository(config: [
            'user_repository' => [
                'table' => 'user',
                'field' => ['identity' => 'email', 'password' => 'password'],
                'sql_get_details' => 'SELECT email, password FROM user WHERE email = :identity',
            ],
        ])->authenticate('ana@example.com', 'secret');
        $this->assertNotNull($asked);
        $this->assertSame(['email' => 'ana@example.com'], $asked->getDetails());
    }

    #[Test]
    public function theColumnOfThePasswordIsTheOneOfTheConfiguration(): void
    {
        $this->database = new UsersDatabase(
            [['identity' => '11111111-1', 'password' => 'clave', 'roles' => []]],
            table: 'people',
            identity: 'rut',
            password: 'secret'
        );

        $user = (new DatabaseUserRepository($this->database->config()))->authenticate('11111111-1', 'clave');

        $this->assertNotNull($user);
        $this->assertSame(['id', 'rut', 'name'], array_keys($user->getDetails()));
    }

    #[Test]
    public function theHashOfAnOldPasswordIsMadeAgainWhenTheUserLogsIn(): void
    {
        $old = password_hash('secret', PASSWORD_BCRYPT, ['cost' => 4]);
        $this->database = new UsersDatabase([
            ['identity' => 'ana@example.com', 'password' => 'secret', 'roles' => [], 'hash' => $old],
        ]);
        $repository = new DatabaseUserRepository($this->database->config());

        $user = $repository->authenticate('ana@example.com', 'secret');

        $this->assertNotNull($user);
        $new = $this->database->hash('ana@example.com');
        $this->assertNotSame($old, $new);
        $this->assertFalse(password_needs_rehash($new, PASSWORD_DEFAULT));
        $this->assertTrue(password_verify('secret', $new));

        // Once it is the current one, it is not made again.
        $repository->authenticate('ana@example.com', 'secret');
        $this->assertSame($new, $this->database->hash('ana@example.com'));
    }

    #[Test]
    public function theHashIsNotMadeAgainWhenThePasswordIsWrong(): void
    {
        $old = password_hash('secret', PASSWORD_BCRYPT, ['cost' => 4]);
        $this->database = new UsersDatabase([
            ['identity' => 'ana@example.com', 'password' => 'secret', 'roles' => [], 'hash' => $old],
        ]);

        $user = (new DatabaseUserRepository($this->database->config()))->authenticate('ana@example.com', 'wrong');

        $this->assertNull($user);
        $this->assertSame($old, $this->database->hash('ana@example.com'));
    }

    #[Test]
    public function aUserThatDoesNotExistTakesAsLongAsOneThatDoes(): void
    {
        $repository = $this->repository();
        $time = static function (callable $attempt): float {
            $times = [];
            for ($i = 0; $i < 3; $i++) {
                $start = hrtime(true);
                $attempt();
                $times[] = hrtime(true) - $start;
            }
            sort($times);

            return $times[1];
        };

        $known = $time(fn () => $repository->authenticate('ana@example.com', 'wrong'));
        $unknown = $time(fn () => $repository->authenticate('nobody@example.com', 'wrong'));

        // The password is hashed with bcrypt: it is most of the time of the
        // attempt of a user that exists, and it must be also of the one that does
        // not (without it, it is a few thousandths of the time).
        $this->assertGreaterThan($known * 0.3, $unknown);
    }

    #[Test]
    public function theConnectionIsMadeWhenItIsNeededNotBefore(): void
    {
        $config = new DatabaseConfiguration(['database_url' => 'sqlite:/a/directory/that/does/not/exist/users.db']);

        // It is built: it does not connect.
        $repository = new DatabaseUserRepository($config);

        $this->expectException(\PDOException::class);

        $repository->authenticate('ana@example.com', 'secret');
    }

    #[Test]
    public function aConnectionThatIsGivenIsTheOneThatIsUsed(): void
    {
        $this->database = new UsersDatabase();
        // The URL of the configuration is of nowhere: the connection is the one given.
        $config = $this->database->config(['database_url' => 'sqlite:/nowhere/users.db']);
        $pdo = new \PDO('sqlite:' . $this->database->file());

        $user = (new DatabaseUserRepository($config, $pdo))->authenticate('ana@example.com', 'secret');

        $this->assertSame('ana@example.com', $user?->getIdentity());
    }

    #[Test]
    public function theRolesComeFromTheQueryOfTheConfiguration(): void
    {
        $repository = $this->repository(config: [
            'user_repository' => [
                'table' => 'user',
                'field' => ['identity' => 'email', 'password' => 'password'],
                'sql_get_roles' => "SELECT 'from-query' AS name WHERE :identity IS NOT NULL",
            ],
        ]);

        $this->assertSame(['from-query'], $repository->authenticate('ana@example.com', 'secret')?->getRoles());
    }

    #[Test]
    public function aUserIsFoundByItsIdentityWithItsRolesAndDetailsAndWithoutThePassword(): void
    {
        $repository = $this->repository([
            ['identity' => 'ana@example.com', 'password' => 'one', 'roles' => ['admin', 'editor']],
            ['identity' => 'ben@example.com', 'password' => 'two', 'roles' => ['viewer']],
        ]);

        $user = $repository->find('ben@example.com');

        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('ben@example.com', $user->getIdentity());
        $this->assertSame(['viewer'], $user->getRoles());
        $this->assertSame('User 2', $user->getDetails()['name']);
        $this->assertArrayNotHasKey('password', $user->getDetails());
    }

    #[Test]
    public function aUserThatIsNotThereIsNotFound(): void
    {
        $repository = $this->repository();

        $this->assertNull($repository->find('nobody@example.com'));

        $this->database?->delete('ana@example.com');
        $this->assertNull($repository->find('ana@example.com'));
    }

    #[Test]
    public function findingAUserDoesNotNeedItsPasswordAndDoesNotChangeIt(): void
    {
        $repository = $this->repository();
        $hash = $this->database?->hash('ana@example.com');

        $repository->find('ana@example.com');

        $this->assertSame($hash, $this->database?->hash('ana@example.com'));
    }
}
