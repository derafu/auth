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

use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\FormManager;
use Derafu\Auth\Provider\Database\DatabaseAuthentication;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\SessionManager;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\UsersDatabase;
use Laminas\Diactoros\Response\RedirectResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What a session knows about its user is a copy of what the database said when
 * the user logged in, and this is when it stops being true: the database is
 * asked again every `refresh_interval` seconds (5 minutes if nothing says
 * another number), with the identity that the session has.
 */
#[CoversClass(DatabaseAuthentication::class)]
#[CoversClass(DatabaseUserRepository::class)]
#[UsesClass(SessionManager::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authorization::class)]
#[UsesClass(\Derafu\Auth\Exception\FormException::class)]
#[UsesClass(FormManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\DatabaseConfiguration::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\LoginThrottle::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\Form\LoginForm::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
final class DatabaseRefreshTest extends TestCase
{
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

    /**
     * @param array<string, mixed> $config
     */
    private function authentication(array $config = []): DatabaseAuthentication
    {
        $config = $this->database->config($config + [
            'enabled' => true,
            'protected_paths' => ['/private'],
            'unauthorized_redirect_route' => '/auth/login',
        ]);

        return new DatabaseAuthentication(
            new DatabaseUserRepository($config),
            $config,
            new SessionManager(),
            new FormManager(
                new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
                $this->app->processor(),
                $config
            )
        );
    }

    /**
     * The login of `ana`. It gives the identifier of the session.
     */
    private function logIn(DatabaseAuthentication $authentication): string
    {
        $response = $this->app->handle(
            $this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'secret']),
            fn (ServerRequestInterface $request): null => $authentication->authenticate($request) === null ? null : null
        );

        return $this->app->sessionId($response);
    }

    /**
     * The user asks for a protected page with the session.
     *
     * @return array{ResponseInterface, UserInterface|null} The response and the
     * user that the page got (null if the user was sent away).
     */
    private function visit(DatabaseAuthentication $authentication, string $sid): array
    {
        $user = null;
        $response = $this->app->handle(
            $this->app->request('/private/page', sid: $sid),
            function (ServerRequestInterface $request) use ($authentication, &$user): ?ResponseInterface {
                $user = $authentication->authenticate($request);

                return $user === null ? $authentication->unauthorizedResponse($request) : null;
            }
        );

        return [$response, $user];
    }

    #[Test]
    public function theRolesAreTheOnesOfTheLoginUntilTheIntervalPassesAndThenTheOnesOfTheDatabase(): void
    {
        $authentication = $this->authentication();
        $sid = $this->logIn($authentication);
        $this->database->setRoles('ana@example.com', ['editor', 'accountant']);

        // The database changed, the session has not been asked yet.
        $first = $this->visit($authentication, $sid);
        $this->assertSame(['admin'], $first[1]?->getRoles());

        // 299 seconds: not yet. 300: asked again.
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 299;
        $second = $this->visit($authentication, $sid);
        $this->assertSame(['admin'], $second[1]?->getRoles());

        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 300;
        $third = $this->visit($authentication, $sid);

        $this->assertEqualsCanonicalizing(['editor', 'accountant'], $third[1]?->getRoles());
        // The session has the new roles, and a new time for the next check.
        $this->assertEqualsCanonicalizing(['editor', 'accountant'], $this->app->persistence->store[$sid]['user']['roles']);
        $this->assertEqualsWithDelta(time(), $this->app->persistence->store[$sid]['auth_checked_at'], 2);
    }

    #[Test]
    public function theIntervalCanBeShorterOrLongerThanTheDefault(): void
    {
        $short = $this->authentication(['refresh_interval' => 60]);
        $sid = $this->logIn($short);
        $this->database->setRoles('ana@example.com', ['editor']);

        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 61;
        $this->assertSame(['editor'], $this->visit($short, $sid)[1]?->getRoles());

        // With an interval of an hour, 10 minutes is not enough.
        $long = $this->authentication(['refresh_interval' => 3600]);
        $this->database->setRoles('ana@example.com', ['accountant']);
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 600;
        $this->assertSame(['editor'], $this->visit($long, $sid)[1]?->getRoles());
    }

    #[Test]
    public function theDetailsAreRenewedWithTheRoles(): void
    {
        $authentication = $this->authentication();
        $sid = $this->logIn($authentication);
        $this->database->setName('ana@example.com', 'Ana Perez');
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 301;

        $user = $this->visit($authentication, $sid)[1];

        $this->assertSame('Ana Perez', $user?->getDetails()['name']);
        $this->assertArrayNotHasKey('password', $this->app->persistence->store[$sid]['user']['details']);
    }

    #[Test]
    public function aUserThatIsNotInTheDatabaseAnymoreLosesTheSession(): void
    {
        $authentication = $this->authentication();
        $sid = $this->logIn($authentication);
        $this->database->delete('ana@example.com');
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 301;

        [$response, $user] = $this->visit($authentication, $sid);

        $this->assertNull($user);
        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame('/auth/login', $response->getHeaderLine('Location'));
        $this->assertArrayNotHasKey('user', $this->app->persistence->store[$sid]);
        $this->assertArrayNotHasKey('auth_checked_at', $this->app->persistence->store[$sid]);
    }

    #[Test]
    public function aDatabaseThatFailsDoesNotCloseTheSessionAndTheNextRequestContinuesIt(): void
    {
        $authentication = $this->authentication();
        $sid = $this->logIn($authentication);
        $session = $this->app->persistence->store[$sid];
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 301;

        $this->database->break();
        [$response, $user] = $this->visit($authentication, $sid);
        $this->database->repair();

        // The user can not be verified, so the page does not run, but the session
        // is the one that it was.
        $this->assertNull($user);
        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame($session['user'], $this->app->persistence->store[$sid]['user']);

        // The database is back: the same session goes on, without logging in.
        $this->database->setRoles('ana@example.com', ['editor']);
        $this->assertSame(['editor'], $this->visit($authentication, $sid)[1]?->getRoles());
    }

    #[Test]
    public function aSessionMadeBeforeTheTimeOfTheCheckWasKeptIsAskedOnceAndThenHasIt(): void
    {
        $authentication = $this->authentication();
        $sid = $this->logIn($authentication);
        unset($this->app->persistence->store[$sid]['auth_checked_at']);
        $this->database->setRoles('ana@example.com', ['editor']);

        $this->assertSame(['editor'], $this->visit($authentication, $sid)[1]?->getRoles());
        $this->assertArrayHasKey('auth_checked_at', $this->app->persistence->store[$sid]);

        $this->database->setRoles('ana@example.com', ['accountant']);
        $this->assertSame(['editor'], $this->visit($authentication, $sid)[1]?->getRoles());
    }

    #[Test]
    public function aUserThatBecomesInactiveLosesTheSessionWhenTheSessionIsAsked(): void
    {
        $authentication = $this->authentication();
        $sid = $this->logIn($authentication);
        $this->database->setActive('ana@example.com', false);

        // Until the interval passes the session is the copy of the login.
        $first = $this->visit($authentication, $sid);
        $this->assertNotNull($first[1]);

        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 301;
        $second = $this->visit($authentication, $sid);
        [$response, $user] = $second;

        $this->assertNull($user);
        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertArrayNotHasKey('user', $this->app->persistence->store[$sid]);
    }

    #[Test]
    public function withoutTheCheckAnInactiveUserKeepsTheSession(): void
    {
        $authentication = $this->authentication(['user_repository' => ['sql_is_active' => false]]);
        $sid = $this->logIn($authentication);
        $this->database->setActive('ana@example.com', false);
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 301;

        $this->assertNotNull($this->visit($authentication, $sid)[1]);
    }

    #[Test]
    public function aQueryThatDoesNotWorkIsNotTakenForADatabaseThatIsDown(): void
    {
        // The table has no column "active": it is the configuration that is wrong,
        // so it is said, and the session is not kept waiting for a database that
        // is fine.
        $this->database->remove();
        $this->database = new UsersDatabase(withActiveColumn: false);
        $authentication = $this->authentication(['user_repository' => ['sql_is_active' => false]]);
        $sid = $this->logIn($authentication);
        $broken = $this->authentication();
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 301;

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The query "sql_is_active" failed: ');

        $this->visit($broken, $sid);
    }
}
