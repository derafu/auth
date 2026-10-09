<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Keycloak;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Channel\Web\SessionManager;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakController;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\User;
use Derafu\TestsAuth\Fixture\KeycloakBrowser;
use Derafu\TestsAuth\Fixture\RealKeycloak;
use Derafu\TestsAuth\Fixture\RecordingHttpClient;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use Derafu\Translation\TranslatorFactory;
use Firebase\JWT\JWT;
use GuzzleHttp\Psr7\HttpFactory;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * The flow of Keycloak against a real Keycloak (a container of Docker with a
 * realm of the tests, see `RealKeycloak`), through the real middlewares of
 * Mezzio (session, flash and authentication).
 *
 * The user that is not logged in is sent to Keycloak with the state, the nonce
 * and the PKCE challenge. The callback is the login: the code is exchanged once,
 * by the authentication, the tokens are verified with the keys of the realm and
 * the session is renewed. The controller sends the user back to the page that
 * was requested. The logout closes the session of the application and the one
 * of Keycloak.
 */
#[CoversClass(KeycloakWebFlow::class)]
#[CoversClass(KeycloakController::class)]
#[CoversClass(KeycloakTokenVerifier::class)]
#[CoversClass(KeycloakUserRepository::class)]
#[CoversClass(KeycloakSessionManager::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationManager::class)]
#[UsesClass(\Derafu\Auth\Authentication\Identification::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\Flash::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authorization\AccessRules::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\Api\KeycloakBearerScheme::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(SessionManager::class)]
#[UsesClass(User::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationMiddleware::class)]
final class KeycloakFlowTest extends TestCase
{
    private const NEXT = 'Mezzio\Flash\FlashMessagesInterface::FLASH_NEXT';

    private static RealKeycloak $keycloak;

    private SessionApp $app;

    private KeycloakBrowser $browser;

    public static function setUpBeforeClass(): void
    {
        self::$keycloak = RealKeycloak::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$keycloak->stop();
    }

    protected function setUp(): void
    {
        $this->app = new SessionApp();
        $this->browser = new KeycloakBrowser();
    }

    /**
     * @param list<string> $protected
     * @param array<string, mixed> $config
     * @return array{AuthenticationInterface, KeycloakController, KeycloakUserRepository}
     */
    private function keycloak(array $protected = ['/private'], array $config = []): array
    {
        $config = Stack::keycloakConfiguration($config + [
            'keycloak_url' => self::$keycloak->url(),
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'enabled' => true,
            'protected_paths' => $protected,
            'login_redirect_path' => '/home',
            'logout_redirect_path' => '/bye',
        ]);
        $sessionManager = new KeycloakSessionManager();
        $repository = new KeycloakUserRepository($config);

        return [
            Stack::keycloak($repository, $config, $sessionManager),
            new KeycloakController(Stack::webOf($config), $sessionManager),
            $repository,
        ];
    }

    /**
     * The user asks for a protected page: where the authentication sends them.
     */
    private function authorizationUrl(AuthenticationInterface $authentication): string
    {
        $response = $this->app->handleAuthenticated(
            $this->app->request('/private/page', ['tab' => '2']),
            $authentication,
            function (): void {
                $this->fail('The user is not logged in.');
            }
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);

        return $response->getHeaderLine('Location');
    }

    /**
     * Runs the callback through the middlewares, the way an application does.
     *
     * @param array<string, string> $query
     */
    private function handleCallback(
        AuthenticationInterface $authentication,
        KeycloakController $controller,
        array $query,
        ?string $sid = null
    ): ResponseInterface {
        return $this->app->handleAuthenticated(
            $this->app->request('/auth/callback', $query, sid: $sid),
            $authentication,
            fn (ServerRequestInterface $request) => $controller->handle($request)
        );
    }

    /**
     * The whole login: the page, Keycloak and the callback.
     */
    private function logIn(AuthenticationInterface $authentication, KeycloakController $controller): ResponseInterface
    {
        $query = $this->browser->logIn($this->authorizationUrl($authentication));

        return $this->handleCallback($authentication, $controller, $query);
    }

    /**
     * @return array<string, mixed>
     */
    private function session(ResponseInterface $response): array
    {
        $id = $this->app->sessionId($response);
        $this->assertNotSame('', $id);

        return $this->app->persistence->store[$id];
    }

    #[Test]
    public function aUserThatIsNotLoggedInIsSentToKeycloakWithTheStateTheNonceAndThePkceChallenge(): void
    {
        [$authentication] = $this->keycloak();

        $location = $this->authorizationUrl($authentication);

        $this->assertStringStartsWith(self::$keycloak->url() . '/realms/test/protocol/openid-connect/auth?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame('derafu-auth', $query['client_id']);
        $this->assertSame('https://app.test/auth/callback', $query['redirect_uri']);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('openid profile email', $query['scope']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertNotEmpty($query['code_challenge']);

        // What the session keeps for when the user comes back, and the page that
        // was requested (its path and query only).
        $session = $this->app->persistence->store[SessionApp::KNOWN];
        $this->assertSame($query['state'], $session['oauth2_state']);
        $this->assertSame($query['nonce'], $session['oauth2_nonce']);
        $this->assertNotEmpty($session['oauth2_pkce']);
        $this->assertSame('/private/page?tab=2', $session['auth_redirect']);
    }

    #[Test]
    public function theLoginLogsTheUserInRenewsTheSessionAndSendsTheUserBackToThePage(): void
    {
        [$authentication, $controller] = $this->keycloak();

        $response = $this->logIn($authentication, $controller);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame('/private/page?tab=2', $response->getHeaderLine('Location'));

        // The session: new identifier, the user (and its role of the realm), the
        // tokens, nothing of the login that is over, and the message for the
        // next request.
        $this->assertNotSame(SessionApp::KNOWN, $this->app->sessionId($response));
        $this->assertArrayNotHasKey(SessionApp::KNOWN, $this->app->persistence->store);
        $session = $this->session($response);
        $this->assertSame('ana@example.com', $session['user']['email']);
        $this->assertSame('ana', $session['user']['preferred_username']);
        $this->assertSame(['admin'], $session['user']['realm_access']['roles'] ?? []);
        $this->assertNotEmpty($session['oauth2_token']);
        $this->assertNotEmpty($session['oauth2_refresh_token']);
        $this->assertNotEmpty($session['oauth2_id_token']);
        $this->assertGreaterThan(time(), $session['oauth2_expiry']);
        foreach (['oauth2_state', 'oauth2_nonce', 'oauth2_pkce', 'auth_redirect'] as $key) {
            $this->assertArrayNotHasKey($key, $session);
        }
        $this->assertSame('Successfully logged in.', $session[self::NEXT]['success']['value']['message']);
    }

    #[Test]
    public function theUserOfTheSessionHasTheRolesOfTheRealm(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $sid = $this->app->sessionId($this->logIn($authentication, $controller));
        $user = null;

        $this->app->handleAuthenticated(
            $this->app->request('/private/page', sid: $sid),
            $authentication,
            function (ServerRequestInterface $request) use (&$user): void {
                $user = $request->getAttribute(MezzioUserInterface::class);
            }
        );

        $this->assertInstanceOf(User::class, $user);

        // The role of the realm and the one of this client; the roles that the user
        // has in another client of the realm (`account`) are not roles here.
        $this->assertSame(['admin', 'app-editor'], $user->getRoles());
        $this->assertSame('ana@example.com', $user->getEmail());
        $this->assertTrue($user->isEmailVerified());
        $this->assertSame('Ana Perez', $user->getName());
    }

    #[Test]
    public function theLoginWorksInsideAProtectedPath(): void
    {
        // The callback is /auth/callback, and /auth is protected: the login is the
        // way in, so it is not turned away (it used to send the user to Keycloak
        // again, and again).
        [$authentication, $controller] = $this->keycloak(['/auth', '/private']);

        $response = $this->logIn($authentication, $controller);

        $this->assertSame('/private/page?tab=2', $response->getHeaderLine('Location'));
        $this->assertSame('ana@example.com', $this->session($response)['user']['email']);
    }

    #[Test]
    public function theLoginGoesToThePageThatFollowsWhenThereWasNoPageRequested(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $this->authorizationUrl($authentication);
        $location = $this->authorizationUrl($authentication);
        unset($this->app->persistence->store[SessionApp::KNOWN]['auth_redirect']);

        $response = $this->handleCallback($authentication, $controller, $this->browser->logIn($location));

        $this->assertSame('/home', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function keycloakRequiresPkceSoALoginWithoutTheVerifierFails(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $query = $this->browser->logIn($this->authorizationUrl($authentication));
        unset($this->app->persistence->store[SessionApp::KNOWN]['oauth2_pkce']);

        try {
            $this->handleCallback($authentication, $controller, $query);
            $this->fail('It should have failed.');
        } catch (AuthenticationException $e) {
            $this->assertStringStartsWith('Failed to exchange code for token: ', $e->getMessage());
        }

        $this->assertArrayNotHasKey('user', $this->app->persistence->store[SessionApp::KNOWN]);
    }

    #[Test]
    public function anIdTokenThatIsNotOfThisLoginIsRejected(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $query = $this->browser->logIn($this->authorizationUrl($authentication));
        $this->app->persistence->store[SessionApp::KNOWN]['oauth2_nonce'] = 'a nonce of another login';

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The nonce of the token is not the one of the login.');

        $this->handleCallback($authentication, $controller, $query);
    }

    #[Test]
    public function anIdTokenOfAnotherUserThanTheAccessTokenIsRejected(): void
    {
        [, $controller, ] = $this->keycloak();
        $config = Stack::keycloakConfiguration([
            'keycloak_url' => self::$keycloak->url(),
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'enabled' => true,
            'protected_paths' => ['/private'],
        ]);

        // A repository whose ID token (verified as it is) says another user.
        $swapper = new class ($config) extends KeycloakUserRepository {
            public function verifyIdToken(string $idToken, string $nonce): array
            {
                return array_merge(parent::verifyIdToken($idToken, $nonce), ['sub' => 'another-user']);
            }
        };
        $authentication = Stack::keycloak($swapper, $config, new KeycloakSessionManager());

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The user of the ID token is not the user of the access token.');

        $query = $this->browser->logIn($this->authorizationUrl($authentication));
        $this->handleCallback($authentication, $controller, $query);
    }

    #[Test]
    public function aTokenThatWasGivenToAnotherClientIsRejected(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $this->authorizationUrl($authentication);
        $nonce = $this->app->persistence->store[SessionApp::KNOWN]['oauth2_nonce'];
        $sid = $this->app->sessionId($this->logIn($authentication, $controller));
        $session = $this->app->persistence->store[$sid];

        // The same tokens, for an application that is another client of the realm.
        [, , $other] = $this->keycloak(config: ['client_id' => 'another-client']);

        foreach ([
            fn () => $other->getUserInfoFromToken($session['oauth2_token']),
            fn () => $other->verifyIdToken($session['oauth2_id_token'], $nonce),
        ] as $verify) {
            try {
                $verify();
                $this->fail('It should have failed.');
            } catch (AuthenticationException $e) {
                $messages[] = $e->getMessage();
            }
        }

        $this->assertSame(
            ['The token was not given to this client.', 'The audience of the token is not this client.'],
            $messages
        );
    }

    #[Test]
    public function aTokenOfAnotherIssuerIsRejected(): void
    {
        [$authentication, $controller] = $this->keycloak(config: ['issuer' => 'https://another.test/realms/test']);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The issuer of the token is not the realm.');

        $this->logIn($authentication, $controller);
    }

    #[Test]
    public function aCodeCanBeUsedOnlyOnce(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $query = $this->browser->logIn($this->authorizationUrl($authentication));
        $login = $this->app->persistence->store[SessionApp::KNOWN];
        $this->handleCallback($authentication, $controller, $query);

        // The same login (the state, the nonce and the PKCE code) in another
        // session, with the same code: Keycloak does not accept it.
        $this->app->persistence->store['another-session'] = $login;

        try {
            $this->handleCallback($authentication, $controller, $query, 'another-session');
            $this->fail('It should have failed.');
        } catch (AuthenticationException $e) {
            $this->assertStringStartsWith('Failed to exchange code for token: ', $e->getMessage());
        }
    }

    /**
     * @return array<string, array{array<string, string>, array<string, string>, string}>
     */
    public static function provideFailedCallbacks(): array
    {
        return [
            'an error of Keycloak with its description' => [
                ['oauth2_state' => 'state-1'],
                ['error' => 'access_denied', 'error_description' => 'The user denied the access {x}'],
                'The user denied the access {x}',
            ],
            'an error of Keycloak without description' => [
                ['oauth2_state' => 'state-1'],
                ['error' => 'access_denied'],
                'access_denied',
            ],
            'a login that this session did not start' => [
                [],
                ['state' => 'state-1', 'code' => 'code-1'],
                'No state parameter found in the session.',
            ],
            'another state' => [
                ['oauth2_state' => 'state-1'],
                ['state' => 'state-2', 'code' => 'code-1'],
                'State parameter does not match the stored state in the session.',
            ],
            'no state' => [
                ['oauth2_state' => 'state-1'],
                ['code' => 'code-1'],
                'State parameter does not match the stored state in the session.',
            ],
            'no code' => [
                ['oauth2_state' => 'state-1'],
                ['state' => 'state-1'],
                'No authorization code received.',
            ],
            'a code that Keycloak does not accept' => [
                ['oauth2_state' => 'state-1', 'oauth2_pkce' => 'a-code-verifier-of-at-least-forty-three-characters'],
                ['state' => 'state-1', 'code' => 'not-a-code'],
                'Failed to exchange code for token: ',
            ],
        ];
    }

    /**
     * @param array<string, string> $stored
     * @param array<string, string> $query
     */
    #[Test]
    #[DataProvider('provideFailedCallbacks')]
    public function aFailedCallbackIsAnErrorAndDoesNotLogIn(array $stored, array $query, string $message): void
    {
        [$authentication, $controller] = $this->keycloak();
        $this->app->persistence->store[SessionApp::KNOWN] = $stored;

        try {
            $this->handleCallback($authentication, $controller, $query);
            $this->fail('It should have failed.');
        } catch (AuthenticationException $e) {
            $this->assertStringStartsWith($message, $e->getMessage());
        }

        // Nobody is logged in, and the identifier is the same: nothing was done.
        $this->assertArrayHasKey(SessionApp::KNOWN, $this->app->persistence->store);
        $this->assertArrayNotHasKey('user', $this->app->persistence->store[SessionApp::KNOWN]);
    }

    #[Test]
    public function theErrorOfKeycloakIsTheMessageOfTheExceptionAsItComes(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $this->app->persistence->store[SessionApp::KNOWN] = ['oauth2_state' => 'state-1'];

        try {
            $this->handleCallback($authentication, $controller, ['error_description' => 'Invalid user credentials {x}']);
            $this->fail('It should have failed.');
        } catch (AuthenticationException $e) {
            $translator = TranslatorFactory::create('es', [], [new AuthTranslationResourceProvider()]);

            $this->assertSame(400, $e->getCode());
            $this->assertSame('Invalid user credentials {x}', $e->getMessage());
            $this->assertSame('Invalid user credentials {x}', $e->trans($translator));
            $this->assertSame(['message' => 'Invalid user credentials {x}'], $e->getTranslatableMessage()->getParameters());
        }
    }

    #[Test]
    public function theControllerSendsNobodyThatDidNotLogIn(): void
    {
        [, $controller] = $this->keycloak();

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The login was not completed.');

        $controller->handle($this->app->request('/auth/callback'));
    }

    #[Test]
    public function theControllerSendsNobodyThatIsAnonymous(): void
    {
        [, $controller] = $this->keycloak();

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The login was not completed.');

        $this->app->handle(
            $this->app->request('/auth/callback'),
            fn (ServerRequestInterface $request) => $controller->handle(
                $request->withAttribute(MezzioUserInterface::class, new AnonymousUser())
            )
        );
    }

    #[Test]
    public function theLogoutEndsTheSessionInKeycloakToo(): void
    {
        [$authentication, $controller, $repository] = $this->keycloak();
        $sid = $this->app->sessionId($this->logIn($authentication, $controller));
        $before = $this->app->persistence->store[$sid];

        // Keycloak knows the user: asking for the login again does not ask for the
        // password (single sign-on).
        $this->assertSame(302, $this->browser->visit($this->authorizationUrl($authentication))->getStatusCode());

        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/logout', body: [], sid: $sid),
            $authentication,
            function (): void {
                $this->fail('The logout is handled by the authentication.');
            }
        );

        // The user goes to the logout of Keycloak, with who they are (the ID token)
        // and where to come back.
        $this->assertInstanceOf(RedirectResponse::class, $response);
        $location = $response->getHeaderLine('Location');
        $this->assertStringStartsWith(self::$keycloak->url() . '/realms/test/protocol/openid-connect/logout?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame($before['oauth2_id_token'], $query['id_token_hint']);
        $this->assertSame('derafu-auth', $query['client_id']);
        $this->assertSame('https://app.test/bye', $query['post_logout_redirect_uri']);

        // The session of the application is closed and renewed.
        $this->assertNotSame($sid, $this->app->sessionId($response));
        $this->assertArrayNotHasKey($sid, $this->app->persistence->store);
        $session = $this->session($response);
        foreach (['user', 'oauth2_token', 'oauth2_refresh_token', 'oauth2_id_token', 'auth_redirect'] as $key) {
            $this->assertArrayNotHasKey($key, $session);
        }
        $this->assertSame('The session has been closed successfully.', $session[self::NEXT]['success']['value']['message']);

        // Keycloak ends the session and sends the user back to the application.
        $end = $this->browser->visit($location);
        $this->assertSame(302, $end->getStatusCode());
        $this->assertSame('https://app.test/bye', $end->getHeaderLine('Location'));

        // And it is really over: the refresh token does not work, and the login
        // asks for the password again.
        try {
            $repository->refreshToken($before['oauth2_refresh_token']);
            $this->fail('The session of Keycloak should have ended.');
        } catch (AuthenticationException $e) {
            $this->assertStringStartsWith('Failed to refresh token: ', $e->getMessage());
        }
        $this->assertSame(200, $this->browser->visit($this->authorizationUrl($authentication))->getStatusCode());
    }

    #[Test]
    public function theLogoutDoesNotGoToKeycloakWhenItIsNotWanted(): void
    {
        [$authentication, $controller] = $this->keycloak(config: ['end_session' => false]);
        $sid = $this->app->sessionId($this->logIn($authentication, $controller));

        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/logout', body: [], sid: $sid),
            $authentication,
            fn (): null => null
        );

        $this->assertSame('/bye', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function theLogoutWithoutAnIdTokenGoesStraightToThePageThatFollows(): void
    {
        [$authentication] = $this->keycloak();
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['sub' => 'user-1'],
            'oauth2_token' => 'token-1',
        ];

        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/logout', body: []),
            $authentication,
            fn (): null => null
        );

        $this->assertSame('/bye', $response->getHeaderLine('Location'));
        $this->assertArrayNotHasKey('user', $this->session($response));
    }

    #[Test]
    public function theLogoutWorksInsideAProtectedPathAndWithoutALoggedUser(): void
    {
        [$authentication] = $this->keycloak(['/auth']);

        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/logout', body: []),
            $authentication,
            function (): void {
                $this->fail('The logout is handled by the authentication.');
            }
        );

        $this->assertSame('/bye', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function theControllerOfTheLogoutOnlyRedirects(): void
    {
        [, $controller] = $this->keycloak();

        $response = $controller->logout($this->app->request('/auth/logout', body: []));

        $this->assertSame('/bye', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function anExpiredTokenIsRefreshedWithTheRefreshToken(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $sid = $this->app->sessionId($this->logIn($authentication, $controller));
        $before = $this->app->persistence->store[$sid];
        $this->app->persistence->store[$sid]['oauth2_expiry'] = time() - 10;

        $response = $this->app->handleAuthenticated(
            $this->app->request('/private/page', sid: $sid),
            $authentication,
            fn (): null => null
        );

        $session = $this->session($response);
        $this->assertNotSame($before['oauth2_token'], $session['oauth2_token']);
        $this->assertNotEmpty($session['oauth2_id_token']);
        $this->assertGreaterThan(time(), $session['oauth2_expiry']);
        $this->assertSame('ana@example.com', $session['user']['email']);
    }

    #[Test]
    public function anExpiredTokenOfASessionThatKeycloakEndedClosesTheSession(): void
    {
        [$authentication, $controller] = $this->keycloak();
        $sid = $this->app->sessionId($this->logIn($authentication, $controller));
        $logout = $this->app->handleAuthenticated(
            $this->app->request('/auth/logout', body: [], sid: $sid),
            $authentication,
            fn (): null => null
        );
        $this->browser->visit($logout->getHeaderLine('Location'));

        // The same session of the application, as if it had not been closed here.
        $this->app->persistence->store['old'] = $this->app->persistence->store[$sid] ?? [];
        $this->app->persistence->store['old'] += [
            'user' => ['sub' => 'user-1'],
            'oauth2_token' => 'token-1',
            'oauth2_refresh_token' => 'refresh-1',
            'oauth2_expiry' => time() - 10,
        ];

        $response = $this->app->handleAuthenticated(
            $this->app->request('/private/page', sid: 'old'),
            $authentication,
            function (): void {
                $this->fail('The session is closed.');
            }
        );

        // The user goes to Keycloak, and the session has no user.
        $this->assertStringStartsWith(self::$keycloak->url(), $response->getHeaderLine('Location'));
        $this->assertArrayNotHasKey('user', $this->app->persistence->store['old']);
    }

    #[Test]
    public function aTokenThatThisRealmDidNotSignIsRejected(): void
    {
        [, , $repository] = $this->keycloak();
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($key);
        openssl_pkey_export($key, $pem);
        $token = JWT::encode([
            'iss' => self::$keycloak->url() . '/realms/test',
            'azp' => 'derafu-auth',
            'sub' => 'user-1',
            'exp' => time() + 300,
        ], $pem, 'RS256', 'a-key-that-the-realm-does-not-have');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessageMatches('/^Failed to validate the token: /');

        $repository->getUserInfoFromToken($token);
    }

    /**
     * The access token of a login, and a configuration to verify it.
     *
     * @return array{string, KeycloakConfiguration}
     */
    private function accessToken(): array
    {
        [$authentication, $controller] = $this->keycloak();
        $sid = $this->app->sessionId($this->logIn($authentication, $controller));

        return [
            $this->app->persistence->store[$sid]['oauth2_token'],
            Stack::keycloakConfiguration([
                'keycloak_url' => self::$keycloak->url(),
                'realm' => 'test',
                'client_id' => 'derafu-auth',
                'client_secret' => 'test-secret',
                'redirect_uri' => 'https://app.test/auth/callback',
            ]),
        ];
    }

    /**
     * The keys that a realm published before it rotated them: no key of the token.
     */
    private function rotatedKeys(): string
    {
        return (string) json_encode(['keys' => [[
            'kid' => 'a-key-that-was-rotated',
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => 'sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTMWxbJTjvFlzCLtDcOL1fXfkUF4s1gOObLhhiZDjuJoRI3nb7NhMrFcl5GFlP9qKXoSMBjHq5dOXtFx3agF25Q',
            'e' => 'AQAB',
        ]]]);
    }

    #[Test]
    public function theKeysOfTheRealmAreCachedAndReadOnceForAllTheVerifiers(): void
    {
        [$token, $config] = $this->accessToken();
        $pool = new ArrayAdapter();
        $http = new RecordingHttpClient();

        // Two verifiers (two requests of the application) with the same cache.
        foreach ([1, 2] as $request) {
            $claims = (new KeycloakTokenVerifier($config, $pool, $http, new HttpFactory()))->verifyAccessToken($token);
            $this->assertSame('ana', $claims['preferred_username']);
        }

        $this->assertCount(1, $http->requests);
        $this->assertStringEndsWith('/realms/test/protocol/openid-connect/certs', (string) $http->requests[0]->getUri());
    }

    #[Test]
    public function withoutACacheTheKeysAreReadOncePerVerifier(): void
    {
        [$token, $config] = $this->accessToken();
        $http = new RecordingHttpClient();

        $verifier = new KeycloakTokenVerifier($config, null, $http, new HttpFactory());
        $verifier->verifyAccessToken($token);
        $verifier->verifyAccessToken($token);
        $this->assertCount(1, $http->requests);

        (new KeycloakTokenVerifier($config, null, $http, new HttpFactory()))->verifyAccessToken($token);
        $this->assertCount(2, $http->requests);
    }

    #[Test]
    public function aKeyThatIsNotKnownMakesTheVerifierReadTheKeysAgain(): void
    {
        [$token, $config] = $this->accessToken();

        // Without a cache: the first answer is the keys before the rotation, the key
        // of the token is not there, so the keys are read again.
        $http = new RecordingHttpClient([$this->rotatedKeys()]);
        $claims = (new KeycloakTokenVerifier($config, null, $http, new HttpFactory()))->verifyAccessToken($token);
        $this->assertSame('ana', $claims['preferred_username']);
        $this->assertCount(2, $http->requests);

        // With a cache: it has the keys before the rotation (a token that was not
        // of the realm made it read them), and the key of the token is not there:
        // the keys are read again and the token is accepted.
        $pool = new ArrayAdapter();
        $http = new RecordingHttpClient([$this->rotatedKeys()]);
        $verifier = new KeycloakTokenVerifier($config, $pool, $http, new HttpFactory());
        try {
            $verifier->verifyAccessToken($this->tokenOfAnotherRealm());
            $this->fail('It should have failed.');
        } catch (AuthenticationException) {
        }
        $this->assertCount(1, $http->requests);

        $claims = (new KeycloakTokenVerifier($config, $pool, $http, new HttpFactory()))->verifyAccessToken($token);
        $this->assertSame('ana', $claims['preferred_username']);
        $this->assertCount(2, $http->requests);
    }

    /**
     * A token signed with a key that no realm has published.
     */
    private function tokenOfAnotherRealm(): string
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($key);
        openssl_pkey_export($key, $pem);

        return JWT::encode([
            'iss' => self::$keycloak->url() . '/realms/test',
            'azp' => 'derafu-auth',
            'exp' => time() + 300,
        ], $pem, 'RS256', 'a-key-that-the-realm-never-had');
    }

    #[Test]
    public function aKeyThatTheRealmDoesNotHaveIsRejectedWithOrWithoutACache(): void
    {
        [, $config] = $this->accessToken();
        $token = $this->tokenOfAnotherRealm();

        foreach ([new ArrayAdapter(), null] as $pool) {
            $http = new RecordingHttpClient();

            try {
                (new KeycloakTokenVerifier($config, $pool, $http, new HttpFactory()))->verifyAccessToken($token);
                $this->fail('It should have failed.');
            } catch (AuthenticationException $e) {
                $this->assertMatchesRegularExpression('/^Failed to validate the token: /', $e->getMessage());
            }

            // It asked for the keys, and no more times than it can.
            $this->assertGreaterThanOrEqual(1, count($http->requests));
            $this->assertLessThanOrEqual(2, count($http->requests));
        }
    }

    #[Test]
    public function anExpiredTokenIsRejected(): void
    {
        [$authentication, $controller, $repository] = $this->keycloak();
        $sid = $this->app->sessionId($this->logIn($authentication, $controller));
        $token = $this->app->persistence->store[$sid]['oauth2_token'];

        // The same token, an hour later (and more than the leeway of the clocks).
        JWT::$timestamp = time() + 3600;
        try {
            $repository->getUserInfoFromToken($token);
            $this->fail('It should have failed.');
        } catch (AuthenticationException $e) {
            $this->assertStringContainsString('Expired token', $e->getMessage());
        } finally {
            JWT::$timestamp = null;
        }

        $this->assertFalse($repository->isTokenValid('a-token-that-is-not-a-jwt'));
    }
}
