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

use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\FormManager;
use Derafu\Auth\LoginThrottle;
use Derafu\Auth\Provider\Database\DatabaseAuthentication;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\SessionManager;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\UsersDatabase;
use Derafu\TestsAuth\Provider\ApiBasicTests;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * A client of the API that sends its user and its password to the database
 * provider: what every provider does with it, and what is of the database (the
 * roles, the users that are not active).
 */
#[CoversClass(DatabaseAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authorization::class)]
#[UsesClass(FormManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\DatabaseConfiguration::class)]
#[UsesClass(DatabaseUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\Form\LoginForm::class)]
#[UsesClass(LoginThrottle::class)]
#[UsesClass(SessionManager::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
final class DatabaseApiBasicTest extends TestCase
{
    use ApiBasicTests;

    private SessionApp $app;

    private UsersDatabase $database;

    protected function setUp(): void
    {
        $this->app = new SessionApp();
        $this->database = new UsersDatabase();
    }

    protected function tearDown(): void
    {
        $this->database->remove();
    }

    protected function app(): SessionApp
    {
        return $this->app;
    }

    protected function identity(): string
    {
        return 'ana@example.com';
    }

    protected function basic(array $config = [], ?LoginThrottle $throttle = null): AuthenticationInterface
    {
        $config = $this->database->config($config + [
            'enabled' => true,
            'protected_paths' => ['/api', '/private'],
            'unauthorized_redirect_path' => '/auth/login',
        ]);

        return new DatabaseAuthentication(
            new DatabaseUserRepository($config),
            $config,
            new SessionManager(),
            new FormManager(
                new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
                $this->app->processor(),
                $config
            ),
            throttle: $throttle
        );
    }

    #[Test]
    public function theUserHasTheRolesAndTheDetailsThatTheDatabaseSays(): void
    {
        $this->database->setName('ana@example.com', 'Ana Perez');

        $user = $this->call($this->basic(), $this->basicHeader('ana@example.com', 'secret'))['user'];

        $this->assertSame(['admin'], $user?->getRoles());
        $this->assertSame('Ana Perez', $user->getDetail('name'));
        $this->assertArrayNotHasKey('password', $user->getDetails());
    }

    #[Test]
    public function aUserThatIsNotActiveIsNotAuthenticatedEvenWithTheRightPassword(): void
    {
        $this->database->setActive('ana@example.com', false);

        $result = $this->call($this->basic(), $this->basicHeader('ana@example.com', 'secret'));

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
    }

    #[Test]
    public function aUserThatWasDeletedIsNotAuthenticatedInTheNextRequest(): void
    {
        $authentication = $this->basic();
        $this->assertNotNull($this->call($authentication, $this->basicHeader('ana@example.com', 'secret'))['user']);

        // Nothing is kept: the next request asks the database again.
        $this->database->delete('ana@example.com');

        $this->assertNull($this->call($authentication, $this->basicHeader('ana@example.com', 'secret'))['user']);
    }

    #[Test]
    public function theRolesOfTheUserDecideWhatThePathNeeds(): void
    {
        $config = $this->database->config(['enabled' => true, 'protected_paths' => ['/api', '/api/admin' => ['admin'], '/api/billing' => ['billing']]]);

        $this->assertSame(['admin'], $config->allowedRoles('/api/admin/users'));

        $user = $this->call($this->basic(), $this->basicHeader('ana@example.com', 'secret'))['user'];
        $authorization = new \Derafu\Auth\Authorization($config);
        $request = $this->app->request('/api/admin/users');

        $this->assertTrue($authorization->isGranted((string) $user?->getRoles()[0], $request));
        $this->assertFalse($authorization->isGranted('editor', $request));
        $this->assertFalse($authorization->isGranted('admin', $this->app->request('/api/billing/x')));
    }
}
