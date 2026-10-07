<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Htpasswd;

use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\FormManager;
use Derafu\Auth\LoginThrottle;
use Derafu\Auth\Provider\Htpasswd\HtpasswdAuthentication;
use Derafu\Auth\Provider\Htpasswd\HtpasswdUserRepository;
use Derafu\Auth\SessionManager;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\CustomUser;
use Derafu\TestsAuth\Fixture\CustomUserFactory;
use Derafu\TestsAuth\Fixture\HtpasswdFile;
use Derafu\TestsAuth\Fixture\SessionApp;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Flash\FlashMessagesInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Logging in with a user and a password of an `.htpasswd` file, and what the
 * session knows about the user afterwards: nothing but who it is, and the file
 * is read again every `refresh_interval` seconds.
 */
#[CoversClass(HtpasswdAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authorization::class)]
#[UsesClass(\Derafu\Auth\Exception\FormException::class)]
#[UsesClass(FormManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration::class)]
#[UsesClass(HtpasswdUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\Form\LoginForm::class)]
#[UsesClass(LoginThrottle::class)]
#[UsesClass(SessionManager::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
final class HtpasswdAuthenticationTest extends TestCase
{
    private SessionApp $app;

    private HtpasswdFile $file;

    protected function setUp(): void
    {
        $this->app = new SessionApp();
        $this->file = new HtpasswdFile(['ana' => 'secret', 'beto' => 'other']);
    }

    protected function tearDown(): void
    {
        $this->file->remove();
    }

    private function authentication(?LoginThrottle $throttle = null, bool $custom = false): HtpasswdAuthentication
    {
        $config = $this->file->config([
            'enabled' => true,
            'protected_paths' => ['/private'],
            'unauthorized_redirect_path' => '/auth/login',
        ]);
        $factory = $custom ? new CustomUserFactory() : null;

        return new HtpasswdAuthentication(
            new HtpasswdUserRepository($config, $factory),
            $config,
            new SessionManager(),
            new FormManager(
                new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
                $this->app->processor(),
                $config
            ),
            throttle: $throttle,
            userFactory: $factory
        );
    }

    /**
     * A login. It gives the user, the flash messages of the request and the
     * identifier of the session.
     *
     * @return array{user: UserInterface|null, flashes: array<string, mixed>, sid: string}
     */
    private function logIn(HtpasswdAuthentication $authentication, string $identity, string $password, string $address = '203.0.113.7'): array
    {
        $result = ['user' => null, 'flashes' => [], 'sid' => ''];

        $response = $this->app->handle(
            $this->app->request('/auth/login', body: ['username' => $identity, 'password' => $password], address: $address),
            function (ServerRequestInterface $request) use ($authentication, &$result): null {
                $result['user'] = $authentication->authenticate($request);
                $flash = $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE);
                $this->assertInstanceOf(FlashMessagesInterface::class, $flash);
                $result['flashes'] = json_decode((string) json_encode($flash->getFlashes()), true);

                return null;
            }
        );
        $result['sid'] = $this->app->sessionId($response);

        return $result;
    }

    /**
     * A visit to a protected page with a session.
     *
     * @return array{ResponseInterface, UserInterface|null}
     */
    private function visit(HtpasswdAuthentication $authentication, string $sid): array
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
    public function theRightCredentialsLogTheUserInWithoutRolesNorDetails(): void
    {
        $result = $this->logIn($this->authentication(), 'ana', 'secret');

        $this->assertSame('ana', $result['user']?->getIdentity());
        $this->assertSame([], $result['user']->getRoles());
        $this->assertSame(['identity' => 'ana'], $this->app->persistence->store[$result['sid']]['user']);
        // A new identifier for the session of the login.
        $this->assertNotSame(SessionApp::KNOWN, $result['sid']);
    }

    #[Test]
    public function aWrongPasswordAndAnUnknownUserGiveTheSameError(): void
    {
        $authentication = $this->authentication();

        foreach ([['ana', 'wrong'], ['nobody', 'secret']] as [$identity, $password]) {
            $result = $this->logIn($authentication, $identity, $password);

            $this->assertTrue($result['user']?->isAnonymous());
            $this->assertSame('Invalid identity or password.', $result['flashes']['error']['message']);
        }
        $this->assertArrayNotHasKey('user', $this->app->persistence->store[SessionApp::KNOWN]);
    }

    #[Test]
    public function aLoginThatIsNotAFormOrNotValidDoesNotLogIn(): void
    {
        $authentication = $this->authentication();

        $get = null;
        $this->app->handle($this->app->request('/auth/login'), function (ServerRequestInterface $request) use ($authentication, &$get): null {
            $get = $authentication->authenticate($request);

            return null;
        });
        $this->assertTrue($get?->isAnonymous());

        $blank = $this->logIn($authentication, '', 'secret');
        $this->assertTrue($blank['user']?->isAnonymous());
        $this->assertSame('Invalid form data.', $blank['flashes']['error']['message']);

        $noBody = null;
        $this->app->handle(
            $this->app->request('/auth/login')->withMethod('POST'),
            function (ServerRequestInterface $request) use ($authentication, &$noBody): null {
                $noBody = $authentication->authenticate($request);

                return null;
            }
        );
        $this->assertTrue($noBody?->isAnonymous());
    }

    #[Test]
    public function theFailedAttemptsAreLimitedAsInTheDatabaseProvider(): void
    {
        $authentication = $this->authentication(new LoginThrottle(new ArrayAdapter(), maxAttempts: 2, lockSeconds: 600));

        $this->logIn($authentication, 'ana', 'wrong');
        $this->logIn($authentication, 'ana', 'wrong');

        // Blocked: not even the right password is checked.
        $result = $this->logIn($authentication, 'ana', 'secret');
        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertStringContainsString('Too many failed login attempts', $result['flashes']['error']['message']);

        // Another address is not blocked.
        $this->assertSame('ana', $this->logIn($authentication, 'ana', 'secret', '198.51.100.9')['user']?->getIdentity());
    }

    #[Test]
    public function aLoginThatSucceedsClearsTheFailedAttempts(): void
    {
        $throttle = new LoginThrottle(new ArrayAdapter(), maxAttempts: 2, lockSeconds: 600);
        $authentication = $this->authentication($throttle);

        $this->logIn($authentication, 'ana', 'wrong');
        $this->logIn($authentication, 'ana', 'secret');
        // The client that logged in is another session: this one is a client
        // that did not.
        $this->app->persistence->store[SessionApp::KNOWN] = [];
        $this->logIn($authentication, 'ana', 'wrong');

        // One failed attempt after the login, not two.
        $this->assertFalse($throttle->isLimited('ana', '203.0.113.7'));
        $this->logIn($authentication, 'ana', 'wrong');
        $this->assertTrue($throttle->isLimited('ana', '203.0.113.7'));
    }

    #[Test]
    public function theSessionGivesTheUserAndAProtectedPathNeedsIt(): void
    {
        $authentication = $this->authentication();

        [$response, $user] = $this->visit($authentication, SessionApp::KNOWN);
        $this->assertNull($user);
        $this->assertInstanceOf(RedirectResponse::class, $response);

        $sid = $this->logIn($authentication, 'ana', 'secret')['sid'];
        [, $user] = $this->visit($authentication, $sid);

        $this->assertSame('ana', $user?->getIdentity());
    }

    #[Test]
    public function theUserOfTheSessionIsMadeByTheFactory(): void
    {
        $authentication = $this->authentication(custom: true);
        $login = $this->logIn($authentication, 'ana', 'secret');
        $this->assertInstanceOf(CustomUser::class, $login['user']);

        $inSession = $this->visit($authentication, $login['sid'])[1];
        $this->assertInstanceOf(CustomUser::class, $inSession);

        $this->app->persistence->store[$login['sid']]['auth_checked_at'] = time() - 301;
        $checked = $this->visit($authentication, $login['sid'])[1];
        $this->assertInstanceOf(CustomUser::class, $checked);
    }

    #[Test]
    public function theFileIsReadAgainWhenTheIntervalPassesAndAUserThatIsNotInItLosesTheSession(): void
    {
        $authentication = $this->authentication();
        $sid = $this->logIn($authentication, 'ana', 'secret')['sid'];
        $this->file->write(['beto' => 'other']);

        // The file changed, the session has not been asked yet: 299 seconds.
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 299;
        $before = $this->visit($authentication, $sid)[1];
        $this->assertSame('ana', $before?->getIdentity());

        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 300;
        [$response, $user] = $this->visit($authentication, $sid);

        $this->assertNull($user);
        $this->assertSame('/auth/login', $response->getHeaderLine('Location'));
        $this->assertArrayNotHasKey('user', $this->app->persistence->store[$sid]);
        $this->assertArrayNotHasKey('auth_checked_at', $this->app->persistence->store[$sid]);
    }

    #[Test]
    public function aUserThatIsStillInTheFileKeepsTheSessionWithANewTimeForTheNextCheck(): void
    {
        $authentication = $this->authentication();
        $sid = $this->logIn($authentication, 'ana', 'secret')['sid'];
        // A change of the password does not close the session: only the user
        // that is not in the file.
        $this->file->write(['ana' => 'changed']);
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 301;

        $user = $this->visit($authentication, $sid)[1];

        $this->assertSame('ana', $user?->getIdentity());
        $this->assertEqualsWithDelta(time(), $this->app->persistence->store[$sid]['auth_checked_at'], 2);
    }
}
