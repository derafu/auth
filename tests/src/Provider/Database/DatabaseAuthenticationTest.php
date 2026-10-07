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

use Derafu\Auth\FormManager;
use Derafu\Auth\Provider\Database\DatabaseAuthentication;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\Provider\Database\LoginThrottle;
use Derafu\Auth\SessionManager;
use Derafu\Auth\User;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\Routing\ValueObject\Route;
use Derafu\Routing\ValueObject\RouteMatch;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\UsersDatabase;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Flash\FlashMessagesInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * The authentication of the database provider, in a request that goes through
 * the session and flash middlewares: who is the user in each path, what happens
 * with the login (the form, the credentials) and with the unauthorized.
 */
#[CoversClass(DatabaseAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authorization::class)]
#[UsesClass(\Derafu\Auth\Exception\FormException::class)]
#[UsesClass(\Derafu\Auth\FormManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\DatabaseConfiguration::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\DatabaseUserRepository::class)]
#[UsesClass(LoginThrottle::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\Form\LoginForm::class)]
#[UsesClass(\Derafu\Auth\SessionManager::class)]
#[UsesClass(User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
final class DatabaseAuthenticationTest extends TestCase
{
    private const NEXT = 'Mezzio\Flash\FlashMessagesInterface::FLASH_NEXT';

    private const NO_CAPTCHA = 'The captcha is not valid. Try again.';

    private const EXPIRED = 'The form is not valid or has expired. Reload the page and try again.';

    private SessionApp $app;

    private UsersDatabase $database;

    private DatabaseAuthentication $authentication;

    protected function setUp(): void
    {
        $this->app = new SessionApp();
        $this->database = new UsersDatabase();

        $config = $this->database->config([
            'enabled' => true,
            'protected_paths' => ['/private'],
            'unauthorized_redirect_route' => '/auth/login',
        ]);

        $this->authentication = new DatabaseAuthentication(
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

    protected function tearDown(): void
    {
        $this->database->remove();
    }

    /**
     * Authenticates a request and gives the user and the flash messages of that
     * request.
     *
     * @return array{user: \Derafu\Auth\Contract\UserInterface|null, flashes: array<string, mixed>}
     */
    private function authenticate(ServerRequestInterface $request): array
    {
        $result = ['user' => null, 'flashes' => []];

        $this->app->handle($request, function (ServerRequestInterface $request) use (&$result) {
            $result['user'] = $this->authentication->authenticate($request);
            $flash = $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE);
            $this->assertInstanceOf(FlashMessagesInterface::class, $flash);
            // The messages are data: what the session gives back is the same.
            $result['flashes'] = json_decode((string) json_encode($flash->getFlashes()), true);
        });

        return $result;
    }

    #[Test]
    public function aPathThatIsNotProtectedGivesTheAnonymousUser(): void
    {
        $result = $this->authenticate($this->app->request('/public'));

        $this->assertNotNull($result['user']);
        $this->assertTrue($result['user']->isAnonymous());
        $this->assertSame([], $result['flashes']);
    }

    #[Test]
    public function aRouteThatDeclaresRolesProtectsItsPathEvenIfTheSiteDidNotListIt(): void
    {
        $route = new RouteMatch(new Route('panel', '/open', 'PanelController@index', [], [], ['admin']));
        $request = $this->app->request('/open')->withAttribute('derafu.route', $route);

        $this->assertNull($this->authenticate($request)['user']);

        $this->app->persistence->store[SessionApp::KNOWN] = ['user' => ['identity' => 'ana@example.com']];

        $this->assertSame('ana@example.com', $this->identityOf($this->authenticate($request)));
    }

    #[Test]
    public function aRouteWithoutRolesDoesNotProtectItsPath(): void
    {
        $route = new RouteMatch(new Route('home', '/open', 'HomeController@index'));
        $result = $this->authenticate($this->app->request('/open')->withAttribute('derafu.route', $route));

        $this->assertNotNull($result['user']);
        $this->assertTrue($result['user']->isAnonymous());
    }

    #[Test]
    public function aProtectedPathIsNotAuthenticatedWithoutALoggedUser(): void
    {
        $result = $this->authenticate($this->app->request('/private/page'));

        $this->assertNull($result['user']);
    }

    #[Test]
    public function aProtectedPathGivesTheUserOfTheSession(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['identity' => 'ana@example.com', 'roles' => ['admin'], 'details' => ['name' => 'Ana']],
        ];

        $result = $this->authenticate($this->app->request('/private/page'));

        $this->assertInstanceOf(User::class, $result['user']);
        $this->assertSame('ana@example.com', $result['user']->getIdentity());
        $this->assertSame(['admin'], $result['user']->getRoles());
        $this->assertSame('Ana', $result['user']->getDetail('name'));
        $this->assertFalse($result['user']->isAnonymous());
    }

    #[Test]
    public function aSessionUserWithoutRolesNorDetailsHasNone(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = ['user' => ['identity' => 'ana@example.com']];

        $user = $this->authenticate($this->app->request('/private/page'))['user'];

        $this->assertNotNull($user);
        $this->assertSame([], $user->getRoles());
        $this->assertSame([], $user->getDetails());
    }

    #[Test]
    public function theUnauthorizedResponseRedirectsToLoginAndRemembersThePage(): void
    {
        $response = null;
        $this->app->handle(
            $this->app->request('/private/page'),
            function (ServerRequestInterface $request) use (&$response) {
                $response = $this->authentication->unauthorizedResponse($request);
            }
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/auth/login', $response->getHeaderLine('Location'));

        $session = $this->app->persistence->store[SessionApp::KNOWN];
        $this->assertSame('/private/page', $session['auth_redirect']);
        $this->assertSame(
            [
                'message' => 'You must be logged in to access the requested page {path}',
                'parameters' => ['path' => '/private/page'],
                'domain' => 'auth',
                'defaultLocale' => null,
            ],
            $session[self::NEXT]['error']['value']
        );
    }

    #[Test]
    public function aClientOfTheApiThatIsNotAuthenticatedGetsAJsonResponseNotARedirect(): void
    {
        // The session middleware gives a session to every request: it does not
        // make a login of the client of an API.
        $response = $this->app->handleAuthenticated(
            $this->app->request('/api/items'),
            $this->authenticationWithProtected('/api'),
            function (): void {
                $this->fail('The client is not authenticated.');
            }
        );

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
        $this->assertSame(
            [
                'status' => 401,
                'title' => 'Unauthorized',
                'detail' => 'You need to send valid credentials to access this resource.',
            ],
            json_decode((string) $response->getBody(), true)
        );
        // And nothing is remembered for a login: it is not one.
        $this->assertArrayNotHasKey('auth_redirect', $this->app->persistence->store[SessionApp::KNOWN]);
    }

    #[Test]
    public function theLoginPageWithAGetDoesNotLogIn(): void
    {
        $result = $this->authenticate($this->app->request('/auth/login'));

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame([], $result['flashes']);
    }

    #[Test]
    public function aLoginWithAnInvalidFormGivesTheErrorOfTheForm(): void
    {
        $result = $this->authenticate($this->app->request('/auth/login', body: []));

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame(
            ['message' => 'Invalid form data.', 'parameters' => [], 'domain' => 'errors', 'defaultLocale' => null],
            $result['flashes']['error']
        );
    }

    #[Test]
    public function aLoginWithoutABodyIsAFormWithoutData(): void
    {
        // The parsed body of the request is null (some PSR-7 implementations).
        $result = $this->authenticate($this->app->request('/auth/login')->withMethod('POST'));

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame(self::EXPIRED, $result['flashes']['error']['message']);
    }

    #[Test]
    public function aLoginWithoutTheCsrfTokenIsRejectedEvenWithTheRightCredentials(): void
    {
        $result = $this->authenticate($this->app->request(
            '/auth/login',
            body: ['email' => 'ana@example.com', 'password' => 'secret'],
            csrf: false
        ));

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame(
            ['message' => self::EXPIRED, 'parameters' => [], 'domain' => 'errors', 'defaultLocale' => null],
            $result['flashes']['error']
        );
    }

    #[Test]
    public function aLoginWithTheCsrfTokenOfAnotherSessionIsRejected(): void
    {
        $this->app->persistence->store['id-of-eve'] = [];
        $forged = $this->app->token('id-of-eve');

        $result = $this->authenticate($this->app->request(
            '/auth/login',
            body: ['email' => 'ana@example.com', 'password' => 'secret', '_token' => $forged],
            csrf: false
        ));

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame(self::EXPIRED, $result['flashes']['error']['message']);
    }

    #[Test]
    public function aLoginWithoutTheCaptchaIsRejectedEvenWithTheRightCredentials(): void
    {
        $result = $this->authenticate($this->app->request(
            '/auth/login',
            body: ['email' => 'ana@example.com', 'password' => 'secret'],
            captcha: false
        ));

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame(
            ['message' => self::NO_CAPTCHA, 'parameters' => [], 'domain' => 'errors', 'defaultLocale' => null],
            $result['flashes']['error']
        );
    }

    #[Test]
    public function aLoginWithTheCaptchaOfAnotherFormIsRejected(): void
    {
        $result = $this->authenticate($this->app->request(
            '/auth/login',
            body: ['email' => 'ana@example.com', 'password' => 'secret', 'altcha' => $this->app->solvedCaptcha('contact')],
            captcha: false
        ));

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame(self::NO_CAPTCHA, $result['flashes']['error']['message']);
    }

    #[Test]
    public function aLoginWithTheCsrfTokenOfItsSessionIsAccepted(): void
    {
        $result = $this->authenticate($this->app->request(
            '/auth/login',
            body: ['email' => 'ana@example.com', 'password' => 'secret', '_token' => $this->app->token()],
            csrf: false
        ));

        $this->assertSame('ana@example.com', $this->identityOf($result));
    }

    #[Test]
    public function aLoginWithABlankIdentityIsNotValid(): void
    {
        $result = $this->authenticate(
            $this->app->request('/auth/login', body: ['email' => '', 'password' => 'secret'])
        );

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame('Invalid form data.', $result['flashes']['error']['message']);
    }

    #[Test]
    public function aLoginWithAWrongPasswordGivesTheErrorOfTheCredentials(): void
    {
        $result = $this->authenticate(
            $this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'wrong'])
        );

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame(
            ['message' => 'Invalid identity or password.', 'parameters' => [], 'domain' => 'auth', 'defaultLocale' => null],
            $result['flashes']['error']
        );
    }

    #[Test]
    public function aLoginWithAnUnknownIdentityGivesTheSameError(): void
    {
        $result = $this->authenticate(
            $this->app->request('/auth/login', body: ['email' => 'nobody@example.com', 'password' => 'secret'])
        );

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame('Invalid identity or password.', $result['flashes']['error']['message']);
    }

    #[Test]
    public function aLoginWithTheRightCredentialsLogsTheUserInAndSaysIt(): void
    {
        $result = $this->authenticate(
            $this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'secret'])
        );

        $this->assertSame('ana@example.com', $result['user']?->getIdentity());
        $this->assertSame(['admin'], $result['user']->getRoles());

        // The user is in the session (with a new identifier), and the message of
        // the success is for the next request.
        $this->assertCount(1, $this->app->persistence->store);
        $this->assertArrayNotHasKey(SessionApp::KNOWN, $this->app->persistence->store);
        $store = array_values($this->app->persistence->store)[0];
        $this->assertSame('ana@example.com', $store['user']['identity']);
        $this->assertSame(['admin'], $store['user']['roles']);

        // The session does not keep the hash of the password.
        $this->assertSame(['id', 'email', 'name'], array_keys($store['user']['details']));
        $this->assertSame(
            ['message' => 'Successfully logged in.', 'parameters' => [], 'domain' => 'auth', 'defaultLocale' => null],
            $store[self::NEXT]['success']['value']
        );
    }

    #[Test]
    public function theLogoutRemovesTheUserAndSendsTheUserToThePageThatFollows(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['identity' => 'ana@example.com', 'roles' => ['admin'], 'details' => []],
            'auth_redirect' => '/private/page',
        ];

        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/logout', body: []),
            $this->authentication,
            function (): void {
                $this->fail('The logout is handled by the authentication.');
            }
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame('/', $response->getHeaderLine('Location'));
        $this->assertCount(1, $this->app->persistence->store);
        $store = array_values($this->app->persistence->store)[0];
        $this->assertArrayNotHasKey('user', $store);
        $this->assertArrayNotHasKey('auth_redirect', $store);
        $this->assertSame('The session has been closed successfully.', $store[self::NEXT]['success']['value']['message']);
    }

    #[Test]
    public function theLoginPathIsPublicEvenInsideAProtectedPath(): void
    {
        // /auth is protected, and the login is in /auth/login: it is the way in.
        $config = $this->database->config([
            'enabled' => true,
            'protected_paths' => ['/auth'],
        ]);
        $authentication = new DatabaseAuthentication(
            new DatabaseUserRepository($config),
            $config,
            new SessionManager(),
            new FormManager(
                new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
                $this->app->processor(),
                $config
            )
        );
        $users = [];

        foreach ([
            $this->app->request('/auth/login'),
            $this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'wrong']),
            $this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'secret']),
        ] as $request) {
            $this->app->handle($request, function (ServerRequestInterface $request) use ($authentication, &$users) {
                $users[] = $authentication->authenticate($request);
            });
        }

        $this->assertTrue($users[0]?->isAnonymous());
        $this->assertTrue($users[1]?->isAnonymous());
        $this->assertSame('ana@example.com', $users[2]?->getIdentity());
    }

    #[Test]
    public function aLoggedUserThatVisitsTheLoginPageIsStillTheLoggedUser(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['identity' => 'ana@example.com', 'roles' => ['admin'], 'details' => []],
        ];

        $user = $this->authenticate($this->app->request('/auth/login'))['user'];

        $this->assertSame('ana@example.com', $user?->getIdentity());
    }

    #[Test]
    public function theLogoutPathGivesNoUserToTriggerTheLogout(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['identity' => 'ana@example.com', 'roles' => [], 'details' => []],
        ];

        $this->assertNull($this->authenticate($this->app->request('/auth/logout', body: []))['user']);
        $this->assertNull($this->authenticate($this->app->request('/auth/logout', body: []))['user']);
    }

    /**
     * @return array<string, array{string, array<string, string>, bool}>
     */
    public static function provideLogoutRequests(): array
    {
        return [
            'a POST that says nothing about its origin (not a browser)' => ['POST', [], true],
            'a POST from the same origin (Sec-Fetch-Site)' => ['POST', ['Sec-Fetch-Site' => 'same-origin'], true],
            'a POST that the user started (Sec-Fetch-Site none)' => ['POST', ['Sec-Fetch-Site' => 'none'], true],
            'a POST from the same origin (Origin)' => ['POST', ['Origin' => 'https://app.test'], true],
            'a POST from the same origin, with the port of the scheme' => ['POST', ['Origin' => 'https://app.test:443'], true],
            'a POST from another site (Sec-Fetch-Site)' => ['POST', ['Sec-Fetch-Site' => 'cross-site'], false],
            'a POST from a site of the same domain (Sec-Fetch-Site)' => ['POST', ['Sec-Fetch-Site' => 'same-site'], false],
            'a POST from another site (Origin)' => ['POST', ['Origin' => 'https://evil.test'], false],
            'a POST from another port (Origin)' => ['POST', ['Origin' => 'https://app.test:8443'], false],
            'a POST from another scheme (Origin)' => ['POST', ['Origin' => 'http://app.test'], false],
            'a POST from an opaque origin (Origin null)' => ['POST', ['Origin' => 'null'], false],
            'what Sec-Fetch-Site says counts more than Origin' => [
                'POST',
                ['Sec-Fetch-Site' => 'cross-site', 'Origin' => 'https://app.test'],
                false,
            ],
            'a GET' => ['GET', [], false],
            'a GET from the same origin' => ['GET', ['Sec-Fetch-Site' => 'same-origin'], false],
        ];
    }

    /**
     * @param array<string, string> $headers
     */
    #[Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('provideLogoutRequests')]
    public function onlyAPostFromTheSameOriginIsALogout(string $method, array $headers, bool $isLogout): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['identity' => 'ana@example.com', 'roles' => [], 'details' => []],
        ];
        $request = $this->app->request('/auth/logout', body: $method === 'POST' ? [] : null, headers: $headers);

        $user = $this->authenticate($request)['user'];

        if ($isLogout) {
            $this->assertNull($user);
        } else {
            // It is not a logout: the user is still the one of the session, and
            // the request goes on to the controller of the route.
            $this->assertSame('ana@example.com', $user?->getIdentity());
        }
    }

    /**
     * An authentication that limits the failed attempts to 3 in ten minutes, and
     * the repository that it uses, that counts the passwords that it checked.
     *
     * @return array{DatabaseAuthentication, object, ArrayAdapter}
     */
    private function throttled(): array
    {
        $config = $this->database->config(['enabled' => true, 'protected_paths' => ['/private']]);
        $repository = new class ($config) extends DatabaseUserRepository {
            public int $checked = 0;

            public function authenticate(string $credential, ?string $password = null): ?\Derafu\Auth\Contract\UserInterface
            {
                $this->checked++;

                return parent::authenticate($credential, $password);
            }
        };
        $cache = new ArrayAdapter();

        return [
            new DatabaseAuthentication(
                $repository,
                $config,
                new SessionManager(),
                new FormManager(
                    new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
                    $this->app->processor(),
                    $config
                ),
                throttle: new LoginThrottle($cache, maxAttempts: 3, lockSeconds: 600)
            ),
            $repository,
            $cache,
        ];
    }

    /**
     * A login attempt through the middlewares: the user and the flash messages.
     *
     * @return array{user: \Derafu\Auth\Contract\UserInterface|null, flashes: array<string, mixed>}
     */
    private function tryToLogIn(
        DatabaseAuthentication $authentication,
        string $password,
        string $address = '203.0.113.7'
    ): array {
        $result = ['user' => null, 'flashes' => []];
        $request = $this->app->request(
            '/auth/login',
            body: ['email' => 'ana@example.com', 'password' => $password],
            address: $address
        );

        $this->app->handle($request, function (ServerRequestInterface $request) use ($authentication, &$result) {
            $result['user'] = $authentication->authenticate($request);
            $result['flashes'] = json_decode((string) json_encode(
                $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE)->getFlashes()
            ), true);
        });

        return $result;
    }

    #[Test]
    public function afterTooManyFailedAttemptsEvenTheRightPasswordIsNotAccepted(): void
    {
        [$authentication, $repository] = $this->throttled();

        foreach ([1, 2, 3] as $attempt) {
            $this->assertSame('Invalid identity or password.', $this->tryToLogIn($authentication, 'wrong')['flashes']['error']['message']);
        }
        $this->assertSame(3, $repository->checked);

        $result = $this->tryToLogIn($authentication, 'secret');

        $this->assertTrue($result['user']?->isAnonymous());
        $this->assertSame(
            [
                'message' => 'Too many failed login attempts. Try again in {minutes, plural, one {# minute} other {# minutes}}.',
                'parameters' => ['minutes' => 10],
                'domain' => 'auth',
                'defaultLocale' => null,
            ],
            $result['flashes']['error']
        );

        // The password was not even checked.
        $this->assertSame(3, $repository->checked);
    }

    #[Test]
    public function anotherAddressCanLogInWhileOneIsLimited(): void
    {
        [$authentication] = $this->throttled();
        foreach ([1, 2, 3] as $attempt) {
            $this->tryToLogIn($authentication, 'wrong');
        }

        $result = $this->tryToLogIn($authentication, 'secret', '198.51.100.9');

        $this->assertSame('ana@example.com', $this->identityOf($result));
    }

    #[Test]
    public function aLoginThatWorksStartsTheCountAgain(): void
    {
        [$authentication] = $this->throttled();
        $this->tryToLogIn($authentication, 'wrong');
        $this->tryToLogIn($authentication, 'wrong');
        $first = $this->identityOf($this->tryToLogIn($authentication, 'secret'));

        // Two more failures: with the ones before it would be the third.
        $this->tryToLogIn($authentication, 'wrong');
        $this->tryToLogIn($authentication, 'wrong');
        $second = $this->identityOf($this->tryToLogIn($authentication, 'secret'));

        $this->assertSame(['ana@example.com', 'ana@example.com'], [$first, $second]);
    }

    #[Test]
    public function theLimitEndsWithTheWindow(): void
    {
        [$authentication, , $cache] = $this->throttled();
        foreach ([1, 2, 3] as $attempt) {
            $this->tryToLogIn($authentication, 'wrong');
        }
        $this->assertTrue($this->tryToLogIn($authentication, 'secret')['user']?->isAnonymous());

        // Ten minutes later.
        foreach (['auth_login_identity_' . hash('sha256', 'ana@example.com|203.0.113.7')] as $key) {
            $item = $cache->getItem($key);
            $item->set(['count' => 3, 'until' => time() - 1]);
            $cache->save($item);
        }

        $this->assertSame('ana@example.com', $this->identityOf($this->tryToLogIn($authentication, 'secret')));
    }

    #[Test]
    public function aFormThatIsNotValidIsNotAFailedAttempt(): void
    {
        [$authentication] = $this->throttled();

        foreach ([1, 2, 3, 4] as $attempt) {
            $this->authenticate($this->app->request('/auth/login', body: []));
        }

        $this->assertSame('ana@example.com', $this->identityOf($this->tryToLogIn($authentication, 'secret')));
    }

    #[Test]
    public function withoutAThrottleTheAttemptsAreNotLimited(): void
    {
        foreach (range(1, 10) as $attempt) {
            $this->authenticate($this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'wrong']));
        }

        $user = $this->authenticate(
            $this->app->request('/auth/login', body: ['email' => 'ana@example.com', 'password' => 'secret'])
        )['user'];

        $this->assertSame('ana@example.com', $user?->getIdentity());
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function providePathsOfRequests(): array
    {
        return [
            'a path' => ['/private/page', '/private/page'],
            'a path with a query' => ['/private/page?tab=2', '/private/page?tab=2'],
            // A path that starts with two slashes (or a slash and a backslash) is not
            // a path for a browser, it is another site: it is made one. A URI like
            // the one of Laminas already does it; others (it is only a PSR-7
            // interface) give the path as it comes.
            'two slashes' => ['//evil.test/x', '/evil.test/x'],
            'many slashes' => ['////evil.test/x', '/evil.test/x'],
            'a slash and a backslash' => ['/\\evil.test/x', '/evil.test/x'],
        ];
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('providePathsOfRequests')]
    public function thePageThatWasRequestedIsRememberedOnlyAsAPathOfThisSite(string $path, string $stored): void
    {
        [$path, $query] = array_pad(explode('?', $path, 2), 2, '');
        $uri = new class ($path, $query) extends \Laminas\Diactoros\Uri {
            public function __construct(private readonly string $rawPath, private readonly string $rawQuery)
            {
                parent::__construct('https://app.test/x');
            }

            public function getPath(): string
            {
                return $this->rawPath;
            }

            public function getQuery(): string
            {
                return $this->rawQuery;
            }
        };

        $this->app->handleAuthenticated(
            $this->app->request('/x')->withUri($uri),
            $this->authenticationWithProtected('/'),
            fn (): null => null
        );

        $this->assertSame($stored, $this->rememberedPage());
    }

    /**
     * @param array{user: \Derafu\Auth\Contract\UserInterface|null, flashes: array<string, mixed>} $result
     */
    private function identityOf(array $result): ?string
    {
        $user = $result['user'];

        return $user instanceof \Derafu\Auth\Contract\UserInterface ? $user->getIdentity() : null;
    }

    private function rememberedPage(): ?string
    {
        return $this->app->persistence->store[SessionApp::KNOWN]['auth_redirect'] ?? null;
    }

    private function authenticationWithProtected(string $path): DatabaseAuthentication
    {
        $config = $this->database->config(['enabled' => true, 'protected_paths' => [$path]]);

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
}
