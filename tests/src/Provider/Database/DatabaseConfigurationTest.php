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

use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use stdClass;
use Stringable;

/**
 * The configuration of the database provider: where the database is and how its
 * users are read.
 */
#[CoversClass(DatabaseConfiguration::class)]
#[UsesClass(ConfigurationException::class)]
final class DatabaseConfigurationTest extends TestCase
{
    #[Test]
    public function theUserTableAndItsFieldsHaveDefaults(): void
    {
        $config = new DatabaseConfiguration(['database_url' => 'sqlite::memory:']);

        $this->assertSame('sqlite::memory:', $config->getDatabaseUrl());
        $this->assertSame('email', $config->getUserIdentityField());
        $this->assertSame('password', $config->getUserPasswordField());
        $this->assertSame('user', $config->getUserRepository()['table']);
    }

    #[Test]
    public function theUserTableAndItsFieldsCanBeConfigured(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => [
                'table' => 'people',
                'field' => ['identity' => 'rut', 'password' => 'clave'],
            ],
        ]);

        $this->assertSame('rut', $config->getUserIdentityField());
        $this->assertSame('clave', $config->getUserPasswordField());
        $this->assertSame('people', $config->getUserRepository()['table']);
    }

    #[Test]
    public function theQueriesOfRolesAndDetailsAreMadeFromTheTableAndTheIdentityField(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => ['table' => 'people', 'field' => ['identity' => 'rut']],
        ]);
        $repository = $config->getUserRepository();

        $this->assertSame('SELECT * FROM people WHERE rut = :identity', $repository['sql_get_details']);

        $roles = preg_replace('/\s+/', ' ', trim($repository['sql_get_roles']));
        $this->assertSame(
            'SELECT r.name FROM role as r JOIN people_role as ur ON r.id = ur.role_id '
                . 'JOIN people AS u ON ur.user_id = u.id WHERE u.rut = :identity',
            $roles
        );
    }

    #[Test]
    public function theQueriesThatAreGivenReplaceTheDefaultOnes(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => [
                'sql_get_roles' => 'SELECT 1 WHERE :identity',
                'sql_get_details' => 'SELECT 2 WHERE :identity',
            ],
        ]);

        $this->assertSame('SELECT 1 WHERE :identity', $config->getUserRepository()['sql_get_roles']);
        $this->assertSame('SELECT 2 WHERE :identity', $config->getUserRepository()['sql_get_details']);
    }

    #[Test]
    public function theProjectDirectoryIsReplacedInTheDatabaseUrl(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite:%kernel.project_dir%/var/users.db',
            'project_dir' => '/srv/app',
        ]);

        $this->assertSame('sqlite:/srv/app/var/users.db', $config->getDatabaseUrl());
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function provideNamesThatAreNotValid(): array
    {
        return [
            'a table with a query' => [['table' => 'user; DROP TABLE user']],
            'a table with a space' => [['table' => 'my users']],
            'a table with a quote' => [['table' => "user'"]],
            'a table of two schemas' => [['table' => 'a.b.c']],
            'an identity with a comparison' => [['field' => ['identity' => "email = '' OR 1=1 --"]]],
            'a password with a comma' => [['field' => ['password' => 'password, email']]],
            'a name that starts with a number' => [['field' => ['identity' => '1email']]],
            'an empty name' => [['table' => '']],
        ];
    }

    /**
     * @param array<string, mixed> $repository
     */
    #[Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('provideNamesThatAreNotValid')]
    public function theNamesOfTheTableAndTheColumnsAreOnlyNames(array $repository): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('is not valid for a table or a column.');

        new DatabaseConfiguration(['database_url' => 'sqlite::memory:', 'user_repository' => $repository]);
    }

    #[Test]
    public function aTableOfASchemaIsAValidName(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => ['table' => 'auth.user_account'],
        ]);

        $this->assertSame('auth.user_account', $config->getUserRepository()['table']);
    }

    #[Test]
    public function aDatabaseUrlIsRequired(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The database URL is not configured: set AUTH_DATABASE_URL (or DATABASE_URL).');

        (new DatabaseConfiguration([]))->validate();
    }

    #[Test]
    public function aConfigurationWithAUrlIsValid(): void
    {
        (new DatabaseConfiguration(['database_url' => 'sqlite::memory:']))->validate();

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function aUserIsActiveByTheColumnActiveByDefault(): void
    {
        $repository = (new DatabaseConfiguration(['database_url' => 'sqlite::memory:']))->getUserRepository();

        $this->assertSame('active', $repository['field']['active']);
        $this->assertSame('SELECT active FROM user WHERE email = :identity', $repository['sql_is_active']);
    }

    #[Test]
    public function theQueryThatTellsIfAUserIsActiveIsMadeFromTheNamesOfTheConfiguration(): void
    {
        $repository = (new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => [
                'table' => 'people',
                'field' => ['identity' => 'rut', 'active' => 'enabled'],
            ],
        ]))->getUserRepository();

        $this->assertSame('enabled', $repository['field']['active']);
        $this->assertSame('SELECT enabled FROM people WHERE rut = :identity', $repository['sql_is_active']);
    }

    #[Test]
    public function theQueryThatTellsIfAUserIsActiveCanBeTheOneOfTheApplication(): void
    {
        $sql = 'SELECT COUNT(*) FROM person WHERE rut = :identity AND banned_at IS NULL';

        $repository = (new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => ['sql_is_active' => $sql],
        ]))->getUserRepository();

        $this->assertSame($sql, $repository['sql_is_active']);
    }

    #[Test]
    public function theCheckThatAUserIsActiveCanBeTurnedOffWithFalseOrTheTextFalse(): void
    {
        foreach ([false, 'false', 'FALSE'] as $off) {
            $repository = (new DatabaseConfiguration([
                'database_url' => 'sqlite::memory:',
                'user_repository' => ['sql_is_active' => $off],
            ]))->getUserRepository();

            $this->assertNull($repository['sql_is_active'], var_export($off, true));
        }
    }

    #[Test]
    public function theNameOfTheColumnActiveHasToBeAName(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The name "active; DROP TABLE user" is not valid for a table or a column.');

        new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => ['field' => ['active' => 'active; DROP TABLE user']],
        ]);
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function invalidConfigurationTypes(): iterable
    {
        $values = [
            'boolean' => false,
            'integer' => 0,
            'float' => 1.5,
            'array' => [],
            'object' => new stdClass(),
            'Stringable' => new class () implements Stringable {
                public function __toString(): string
                {
                    return 'user';
                }
            },
        ];
        foreach ($values as $type => $value) {
            foreach (['database_url', 'project_dir'] as $key) {
                yield $key . ' as ' . $type => [[$key => $value], $key];
            }
            foreach (['table', 'sql_get_roles', 'sql_get_details'] as $key) {
                yield $key . ' as ' . $type => [['user_repository' => [$key => $value]], $key];
            }
            foreach (['identity', 'password', 'active'] as $key) {
                yield $key . ' as ' . $type => [['user_repository' => ['field' => [$key => $value]]], $key];
            }
            if ($value !== false) {
                yield 'sql_is_active as ' . $type => [['user_repository' => ['sql_is_active' => $value]], 'sql_is_active'];
            }
        }
        yield 'sql_is_active as true' => [['user_repository' => ['sql_is_active' => true]], 'sql_is_active'];

        foreach (['string' => 'user', 'boolean' => false, 'integer' => 0, 'object' => new stdClass()] as $type => $value) {
            yield 'user_repository as ' . $type => [['user_repository' => $value], 'user_repository'];
            yield 'field as ' . $type => [['user_repository' => ['field' => $value]], 'field'];
        }
    }

    /** @param array<string, mixed> $values */
    #[DataProvider('invalidConfigurationTypes')]
    public function testRejectsInvalidTypesBeforeBuildingQueries(array $values, string $key): void
    {
        $this->expectException(TranslatableInvalidArgumentException::class);
        $this->expectExceptionMessage('"' . $key . '"');

        new DatabaseConfiguration($values);
    }

    public function testNullValuesKeepTheDefaultUrlNamesAndQueries(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => null,
            'project_dir' => null,
            'user_repository' => [
                'table' => null,
                'field' => ['identity' => null, 'password' => null, 'active' => null],
                'sql_get_roles' => null,
                'sql_get_details' => null,
                'sql_is_active' => null,
            ],
        ]);

        $this->assertSame('', $config->getDatabaseUrl());
        $this->assertSame((new DatabaseConfiguration([]))->getUserRepository(), $config->getUserRepository());
    }

    public function testNullRepositoryAndNullFieldsKeepTheDefaults(): void
    {
        $defaults = (new DatabaseConfiguration([]))->getUserRepository();

        $this->assertSame($defaults, (new DatabaseConfiguration(['user_repository' => null]))->getUserRepository());
        $this->assertSame($defaults, (new DatabaseConfiguration(['user_repository' => ['field' => null]]))->getUserRepository());
    }

    public function testEmptyRoleAndDetailQueriesArePreserved(): void
    {
        $config = new DatabaseConfiguration([
            'user_repository' => ['sql_get_roles' => '', 'sql_get_details' => ''],
        ]);

        $this->assertSame('', $config->getUserRepository()['sql_get_roles']);
        $this->assertSame('', $config->getUserRepository()['sql_get_details']);
    }

    /** @return iterable<string, array{string|false|null, string|null}> */
    public static function activeQueryOptions(): iterable
    {
        yield 'null uses the default' => [null, 'SELECT active FROM user WHERE email = :identity'];
        yield 'empty string uses the default' => ['', 'SELECT active FROM user WHERE email = :identity'];
        yield 'false disables the check' => [false, null];
        yield 'false text disables the check' => ['false', null];
        yield 'mixed case and spaces disable the check' => ['  FaLsE  ', null];
        yield 'custom query keeps its spaces' => [' SELECT 1 ', ' SELECT 1 '];
        yield 'zero remains a query string' => ['0', '0'];
    }

    #[DataProvider('activeQueryOptions')]
    public function testPreservesTheActiveQueryPolicy(string|false|null $value, ?string $expected): void
    {
        $config = new DatabaseConfiguration(['user_repository' => ['sql_is_active' => $value]]);

        $this->assertSame($expected, $config->getUserRepository()['sql_is_active']);
    }

    /** @return iterable<string, array{string|null}> */
    public static function emptyProjectDirectories(): iterable
    {
        yield 'null' => [null];
        yield 'empty string' => [''];
        yield 'string zero' => ['0'];
    }

    #[DataProvider('emptyProjectDirectories')]
    public function testEmptyProjectDirectoriesKeepTheUrlPlaceholder(?string $directory): void
    {
        $url = 'sqlite:%kernel.project_dir%/users.db';
        $config = new DatabaseConfiguration(['database_url' => $url, 'project_dir' => $directory]);

        $this->assertSame($url, $config->getDatabaseUrl());
    }
}
