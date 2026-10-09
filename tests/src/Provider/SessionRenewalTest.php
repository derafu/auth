<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider;

use Derafu\Auth\Authentication\Channel\Web\FormManager;
use Derafu\Auth\Authentication\Channel\Web\SessionManager;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\Provider\Database\Web\DatabaseWebFlow;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use Derafu\TestsAuth\Fixture\UsersDatabase;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The session id is renewed when the user logs in and when the user logs out,
 * so an identifier that was known before is of no use after (session fixation).
 *
 * The requests go through the real middlewares of Mezzio (session, flash and
 * authentication), with a session persistence that keeps the contract of the one
 * of PHP, and the database provider works with a real SQLite database. The
 * renewal in Keycloak is tested with its flow (`KeycloakFlowTest`).
 */
#[CoversClass(SessionManager::class)]
#[CoversClass(DatabaseWebFlow::class)]
#[UsesClass(\Derafu\Auth\Authentication\SameOrigin::class)]
#[UsesClass(\Derafu\Auth\Authentication\LoginThrottle::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationManager::class)]
#[UsesClass(\Derafu\Auth\Authentication\Identification::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\Flash::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authorization\AccessRules::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\Scheme\BasicScheme::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\Api\DatabaseBasicScheme::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(FormManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\DatabaseConfiguration::class)]
#[UsesClass(DatabaseUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\Web\Form\LoginForm::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationMiddleware::class)]
final class SessionRenewalTest extends TestCase
{
    private const KNOWN = SessionApp::KNOWN;

    private SessionApp $app;

    private ?UsersDatabase $database = null;

    protected function setUp(): void
    {
        $this->app = new SessionApp();
        $this->app->persistence->store[self::KNOWN] = ['visited' => true];
    }

    protected function tearDown(): void
    {
        $this->database?->remove();
        $this->database = null;
    }

    private function database(): AuthenticationInterface
    {
        $this->database = new UsersDatabase();
        $config = $this->database->config(['enabled' => true, 'protected_paths' => ['/private']]);

        return Stack::database(
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

    #[Test]
    public function theDatabaseLoginRenewsTheSessionIdAndKeepsTheData(): void
    {
        $authentication = $this->database();
        $user = null;

        $response = $this->app->handle(
            $this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'secret']),
            function (ServerRequestInterface $request) use ($authentication, &$user) {
                $user = $authentication->authenticate($request);

                return null;
            }
        );

        $this->assertNotNull($user);
        $this->assertSame('ana@example.com', $user->getIdentity());

        $id = $this->app->sessionId($response);
        $this->assertNotSame('', $id);
        $this->assertNotSame(self::KNOWN, $id);

        // The identifier that was known is destroyed, and the data goes to the new.
        $this->assertArrayNotHasKey(self::KNOWN, $this->app->persistence->store);
        $this->assertTrue($this->app->persistence->store[$id]['visited']);
        $this->assertSame('ana@example.com', $this->app->persistence->store[$id]['user']['identity']);
    }

    #[Test]
    public function aFailedDatabaseLoginDoesNotRenewTheSession(): void
    {
        $authentication = $this->database();

        $response = $this->app->handle(
            $this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'wrong']),
            function (ServerRequestInterface $request) use ($authentication): void {
                $authentication->authenticate($request);
            }
        );

        $this->assertSame(self::KNOWN, $this->app->sessionId($response) ?: self::KNOWN);
        $this->assertArrayHasKey(self::KNOWN, $this->app->persistence->store);
        $this->assertArrayNotHasKey('user', $this->app->persistence->store[self::KNOWN]);
    }

    #[Test]
    public function theLogoutRenewsTheSessionIdAndRemovesTheUser(): void
    {
        $authentication = $this->database();
        $this->app->persistence->store[self::KNOWN] = [
            'user' => ['identity' => 'ana@example.com', 'roles' => [], 'details' => []],
            'auth_checked_at' => time(),
        ];

        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/logout', body: []),
            $authentication,
            function (): void {
                $this->fail('The logout is handled by the authentication.');
            }
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $id = $this->app->sessionId($response);
        $this->assertNotSame('', $id);
        $this->assertNotSame(self::KNOWN, $id);
        $this->assertArrayNotHasKey(self::KNOWN, $this->app->persistence->store);
        $this->assertArrayNotHasKey('user', $this->app->persistence->store[$id]);
    }

    #[Test]
    public function aSessionThatCanNotBeRenewedInPlaceIsAnError(): void
    {
        // The plain session of Mezzio is immutable: it answers with another one.
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('can not be renewed in place');

        (new SessionManager())->regenerate(new Session([], 'an-id'));
    }
}
