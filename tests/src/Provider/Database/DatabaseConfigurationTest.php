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

use Derafu\Auth\Abstract\AbstractProviderConfiguration;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The configuration of the database provider and the base one that every
 * provider shares (protected paths, login and logout, redirects and enabled).
 */
#[CoversClass(DatabaseConfiguration::class)]
#[CoversClass(AbstractProviderConfiguration::class)]
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
        $this->expectExceptionMessage('Database URL is required.');

        (new DatabaseConfiguration([]))->validate();
    }

    #[Test]
    public function aConfigurationWithAUrlIsValid(): void
    {
        (new DatabaseConfiguration(['database_url' => 'sqlite::memory:']))->validate();

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function theValuesAreReadByKeyAndAsAnArray(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'login_path' => '/in',
        ]);

        $this->assertSame('sqlite::memory:', $config->get('database_url'));
        $this->assertSame('user', $config->get('user_repository')['table']);
        $this->assertSame('/in', $config->get('login_path'));
        $this->assertSame('default', $config->get('nothing', 'default'));
        $this->assertSame('sqlite::memory:', $config->toArray()['database_url']);
        $this->assertSame('/in', $config->toArray()['login_path']);
    }

    #[Test]
    public function theBaseConfigurationHasDefaults(): void
    {
        $config = new DatabaseConfiguration(['database_url' => 'sqlite::memory:']);

        $this->assertSame([], $config->getProtectedPaths());
        $this->assertSame('/auth/login', $config->getLoginPath());
        $this->assertSame('/auth/logout', $config->getLogoutPath());
        $this->assertSame('/', $config->getLoginRedirectRoute());
        $this->assertSame('/', $config->getLogoutRedirectRoute());
        $this->assertSame('/', $config->getUnauthorizedRedirectRoute());
        $this->assertTrue($config->isEnabled());
    }

    #[Test]
    public function theProtectedPathsAreAListOrAMapWithTheirRoles(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'protected_paths' => ['/private', '/admin' => 'admin', '/staff' => ['editor', 'admin']],
        ]);

        $this->assertSame(
            ['/private' => [], '/admin' => ['admin'], '/staff' => ['editor', 'admin']],
            $config->getProtectedPaths()
        );
    }

    #[Test]
    public function aPathRequiresAuthenticationWhenItStartsWithAProtectedPath(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'protected_paths' => ['/private', '/admin' => 'admin'],
        ]);

        $this->assertTrue($config->requiresAuth('/private'));
        $this->assertTrue($config->requiresAuth('/private/page'));
        $this->assertTrue($config->requiresAuth('/admin/users'));
        $this->assertFalse($config->requiresAuth('/public'));
        $this->assertFalse($config->requiresAuth('/'));

        $this->assertSame([], $config->allowedRoles('/private/page'));
        $this->assertSame(['admin'], $config->allowedRoles('/admin/users'));
        $this->assertSame([], $config->allowedRoles('/public'));
    }

    #[Test]
    public function aDisabledAuthenticationProtectsNothing(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'protected_paths' => ['/admin' => 'admin'],
            'enabled' => false,
        ]);

        $this->assertFalse($config->isEnabled());
        $this->assertFalse($config->requiresAuth('/admin/users'));
        $this->assertSame([], $config->allowedRoles('/admin/users'));
    }

    #[Test]
    public function thePathsAndTheRedirectsCanBeConfigured(): void
    {
        $config = new DatabaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'login_path' => '/in',
            'logout_path' => '/out',
            'login_redirect_route' => '/home',
            'logout_redirect_route' => '/bye',
            'unauthorized_redirect_route' => '/in',
        ]);

        $this->assertSame('/in', $config->getLoginPath());
        $this->assertSame('/out', $config->getLogoutPath());
        $this->assertSame('/home', $config->getLoginRedirectRoute());
        $this->assertSame('/bye', $config->getLogoutRedirectRoute());
        $this->assertSame('/in', $config->getUnauthorizedRedirectRoute());
    }

    #[Test]
    public function theRefreshIntervalIsFiveMinutesByDefault(): void
    {
        $config = new DatabaseConfiguration(['database_url' => 'sqlite::memory:']);

        $this->assertSame(300, $config->getRefreshInterval());
        $this->assertSame(300, $config->get('refresh_interval'));
        $this->assertSame(300, $config->toArray()['refresh_interval']);
    }

    #[Test]
    public function theRefreshIntervalCanBeConfiguredAndZeroIsTheDefault(): void
    {
        $this->assertSame(
            45,
            (new DatabaseConfiguration(['database_url' => 'sqlite::memory:', 'refresh_interval' => 45]))
                ->getRefreshInterval()
        );
        $this->assertSame(
            300,
            (new DatabaseConfiguration(['database_url' => 'sqlite::memory:', 'refresh_interval' => 0]))
                ->getRefreshInterval()
        );
    }

    #[Test]
    public function aNegativeRefreshIntervalIsAConfigurationError(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The refresh interval must be a number of seconds, 0 or more.');

        new DatabaseConfiguration(['database_url' => 'sqlite::memory:', 'refresh_interval' => -1]);
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
}
