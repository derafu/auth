<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Keycloak;

use Derafu\Auth\Account\AccountController;
use Derafu\Auth\Authentication\Channel\Web\FormManager;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\AuthorizationException;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakAccount;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakAccountClient;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakApiTokenManager;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakController;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakLoginController;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\Twig\AuthExtension;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Renderer\FormTwigExtension;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\Renderer\Factory\RendererFactory;
use Derafu\TestsAuth\Fixture\KeycloakBrowser;
use Derafu\TestsAuth\Fixture\RealKeycloak;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use Derafu\Translation\TranslatorFactory;
use Derafu\Twig\Extension\TranslationExtension;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * The tokens of the API of a user of Keycloak, with a real Keycloak: the user makes
 * as many as it wants in its profile (it gives its password again), it sees them,
 * uses them in the API and revokes them one by one. Each token is an offline session
 * of its own, so revoking one does not touch the others (nor the session of the
 * login). The token is an offline token that only Keycloak can read, and nothing of
 * the application keeps it.
 */
#[CoversClass(KeycloakAccountClient::class)]
#[CoversClass(KeycloakApiTokenManager::class)]
#[CoversClass(KeycloakAccount::class)]
#[CoversClass(KeycloakLoginController::class)]
#[CoversClass(TokenClaims::class)]
#[CoversClass(\Derafu\Auth\Provider\Keycloak\Api\KeycloakBearerScheme::class)]
#[CoversClass(KeycloakSessionManager::class)]
#[CoversClass(AccountController::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationManager::class)]
#[UsesClass(\Derafu\Auth\Authentication\Identification::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebChannel::class)]
#[UsesClass(WebConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\Flash::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authorization\AccessRules::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Account\ApiToken::class)]
#[UsesClass(\Derafu\Auth\Account\PhpSessionDetails::class)]
#[UsesClass(\Derafu\Auth\Authentication\SameOrigin::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\FormManager::class)]
#[UsesClass(\Derafu\Auth\Exception\FormException::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\Account\Form\ApiTokenForm::class)]
#[UsesClass(\Derafu\Auth\Account\Form\ApiTokenValueForm::class)]
#[UsesClass(\Derafu\Auth\Account\NewApiToken::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(AuthorizationException::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\KeycloakConfiguration::class)]
#[UsesClass(KeycloakUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow::class)]
#[UsesClass(KeycloakController::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\SessionManager::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(AuthExtension::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationMiddleware::class)]
final class KeycloakApiTokensTest extends TestCase
{
    private const ROOT = __DIR__ . '/../../../..';

    private static RealKeycloak $keycloak;

    private SessionApp $app;

    private KeycloakBrowser $browser;

    private KeycloakSessionManager $sessions;

    private KeycloakUserRepository $repository;

    private AuthenticationInterface $authentication;

    private AccountController $account;

    private KeycloakController $login;

    private KeycloakApiTokenManager $manager;

    private KeycloakLoginController $loginRoute;

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

        $config = Stack::keycloakConfiguration([
            'keycloak_url' => self::$keycloak->url(),
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'api_audience' => 'derafu-api',
            'api_client_id' => 'derafu-api',
            'api_client_secret' => 'api-secret',
            'enabled' => true,
            'protected_paths' => ['/private'],
            'login_redirect_path' => '/home',
        ]);
        $this->sessions = new KeycloakSessionManager();
        $this->repository = new KeycloakUserRepository($config);
        $this->authentication = Stack::keycloak(
            $this->repository,
            $config,
            $this->sessions,
            cache: new ArrayAdapter()
        );
        $this->login = new KeycloakController(Stack::webOf($config), $this->sessions);

        $client = new KeycloakAccountClient($config);
        $translator = TranslatorFactory::create('es', ['en'], [new AuthTranslationResourceProvider()]);
        $this->manager = $manager = new KeycloakApiTokenManager($this->repository, $client, $this->sessions, $this->formManager($config), $translator);
        $flow = new \Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow(
            $this->repository,
            $config,
            Stack::webOf($config),
            $this->sessions
        );
        $this->loginRoute = new KeycloakLoginController(Stack::webOf($config), $flow, $this->sessions);

        $routing = new class () extends AbstractExtension {
            public function getFunctions(): array
            {
                return [new TwigFunction(
                    'path',
                    fn (string $name, array $parameters = []): string => '/' . str_replace('_', '/', $name) . ($parameters === [] ? '' : '/' . implode('/', $parameters))
                )];
            }
        };
        $this->account = new AccountController(
            RendererFactory::create([
                'engines' => ['twig'],
                'extra' => false,
                'paths' => [
                    self::ROOT . '/resources/templates',
                    self::ROOT . '/tests/fixtures/templates',
                    self::ROOT . '/vendor/derafu/twig/resources/templates',
                    self::ROOT . '/vendor/derafu/form/resources/templates',
                ],
                'extensions' => [
                    $routing,
                    new TranslationExtension($translator, null, 'es'),
                    new AuthExtension(Stack::webOf($config)),
                    new FormTwigExtension($this->app->renderer()),
                ],
            ]),
            new KeycloakAccount($config, $this->sessions, $client, $manager),
            $this->formManager($config)
        );
    }

    protected function tearDown(): void
    {
        self::$keycloak->admin()->reset();
    }

    /**
     * Runs a request through the middlewares and the authentication, and gives the
     * action what the application would: the request of the user.
     */
    private function formManager(KeycloakConfiguration $config): FormManager
    {
        return new FormManager(
            new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
            $this->app->processor(),
            $config
        );
    }

    private function handle(ServerRequestInterface $request, \Closure $action): ResponseInterface
    {
        return $this->app->handleAuthenticated($request, $this->authentication, $action);
    }

    /**
     * The whole login of a user, as a browser does it: a protected page, Keycloak
     * and the callback. It gives the identifier of the session.
     */
    private function logIn(): string
    {
        $page = $this->app->handleAuthenticated(
            $this->app->request('/private/page'),
            $this->authentication,
            function (): void {
                $this->fail('The user is not logged in.');
            }
        );
        $query = $this->browser->logIn($page->getHeaderLine('Location'), 'otto');

        $response = $this->handle(
            $this->app->request('/auth/callback', $query),
            fn (ServerRequestInterface $request) => $this->login->handle($request)
        );

        return $this->app->sessionId($response);
    }

    /**
     * The user asks for a token in its profile, giving what the form asks.
     *
     * @param array<string, string> $body
     * @param array<string, string> $headers
     */
    private function askForToken(string $sid, array $body, array $headers = ['Sec-Fetch-Site' => 'same-origin']): ResponseInterface
    {
        return $this->handle(
            $this->app->request('/auth/profile/tokens', body: $body, sid: $sid, headers: $headers, captcha: false, form: 'api_token'),
            fn (ServerRequestInterface $request) => $this->account->tokenCreate($request)
        );
    }

    /**
     * A whole token, as the user makes it: it gives the token.
     */
    private function makeToken(string $sid, string $password = 'secret'): string
    {
        $response = $this->askForToken($sid, ['password' => $password]);

        $this->assertInstanceOf(HtmlResponse::class, $response);
        $this->assertSame(1, preg_match('#<textarea[^>]*>([^<]+)</textarea>#', (string) $response->getBody(), $matches));

        return html_entity_decode($matches[1]);
    }

    /**
     * What a program does with a token: it calls the API, and gives the user.
     */
    private function callApi(string $token, ?AuthenticationInterface $authentication = null): ?UserInterface
    {
        $user = null;
        $this->app->handleAuthenticated(
            $this->app->request('/api/items', headers: ['Authorization' => 'Bearer ' . $token]),
            $authentication ?? $this->authentication,
            function (ServerRequestInterface $request) use (&$user): void {
                $found = $request->getAttribute(MezzioUserInterface::class);
                $user = $found instanceof UserInterface && !$found->isAnonymous() ? $found : null;
            }
        );

        return $user;
    }

    /**
     * @return list<\Derafu\Auth\Account\ApiToken>
     */
    private function tokens(string $sid): array
    {
        return $this->manager->list(new Session($this->app->persistence->store[$sid]));
    }

    #[Test]
    public function theLoginRouteSendsTheUserToKeycloakAndRemembersTheNextPage(): void
    {
        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/login', ['next' => '/private/page?tab=2']),
            $this->authentication,
            fn (ServerRequestInterface $request) => $this->loginRoute->login($request)
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertStringStartsWith(self::$keycloak->url() . '/realms/test/protocol/openid-connect/auth?', $response->getHeaderLine('Location'));
        $session = $this->app->persistence->store[SessionApp::KNOWN];
        $this->assertSame('/private/page?tab=2', $session['auth_redirect']);
        $this->assertNotEmpty($session['oauth2_state']);
    }

    #[Test]
    public function theLoginRouteNeverTakesTheUserToAnotherSite(): void
    {
        foreach (['//evil.test/x', '/\\evil.test', 'https://evil.test/', 'page'] as $next) {
            $this->app->handleAuthenticated(
                $this->app->request('/auth/login', ['next' => $next]),
                $this->authentication,
                fn (ServerRequestInterface $request) => $this->loginRoute->login($request)
            );

            $this->assertArrayNotHasKey('auth_redirect', $this->app->persistence->store[SessionApp::KNOWN], $next);
        }
    }

    #[Test]
    public function aUserThatIsAlreadyLoggedInGoesOnToTheNextPage(): void
    {
        $sid = $this->logIn();

        $response = $this->handle(
            $this->app->request('/auth/login', ['next' => '/private/x'], sid: $sid),
            fn (ServerRequestInterface $request) => $this->loginRoute->login($request)
        );

        $this->assertSame('/private/x', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function aTokenIsMadeWithThePasswordAndItIsShownOnce(): void
    {
        $sid = $this->logIn();

        $response = $this->askForToken($sid, ['password' => 'secret']);

        $this->assertInstanceOf(HtmlResponse::class, $response);
        $this->assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        preg_match('#<textarea[^>]*>([^<]+)</textarea>#', (string) $response->getBody(), $matches);
        $token = html_entity_decode($matches[1]);
        $this->assertTrue(TokenClaims::isOffline($token));

        // Nothing keeps it: not the session.
        $this->assertStringNotContainsString($token, json_encode($this->app->persistence->store[$sid], JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function aWrongOrMissingPasswordMakesNoToken(): void
    {
        $sid = $this->logIn();

        foreach ([['password' => 'wrong'], ['password' => ''], []] as $body) {
            $response = $this->askForToken($sid, $body);

            $this->assertInstanceOf(RedirectResponse::class, $response);
            $this->assertSame('/auth/profile#api:tokens', $response->getHeaderLine('Location'));
        }
        $this->assertSame(0, self::$keycloak->admin()->offlineSessions('otto', 'derafu-auth'));
    }

    #[Test]
    public function aClientWithoutDirectAccessGrantsSaysWhatToTurnOn(): void
    {
        // The client `derafu-api` of the realm has no direct access grants.
        $config = Stack::keycloakConfiguration([
            'keycloak_url' => self::$keycloak->url(),
            'realm' => 'test',
            'client_id' => 'derafu-api',
            'client_secret' => 'api-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
        ]);
        $manager = new KeycloakApiTokenManager(
            new KeycloakUserRepository($config),
            new KeycloakAccountClient($config),
            $this->sessions,
            $this->formManager($config)
        );
        $request = $this->app->request('/auth/profile/tokens', body: ['password' => 'secret'], captcha: false, form: 'api_token')
            ->withAttribute(MezzioUserInterface::class, new \Derafu\Auth\User('7d5e590b', [], ['preferred_username' => 'otto']));

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('direct access grants');

        $this->app->handle($request, fn (ServerRequestInterface $request) => $manager->create($request, new Session([])));
    }

    #[Test]
    public function theTokenOpensTheApiAsItsUserWithTheRolesOfKeycloak(): void
    {
        $token = $this->makeToken($this->logIn());

        $user = $this->callApi($token);

        $this->assertNotNull($user);
        $this->assertSame('otto', $user->getUsername());
        // The roles of the realm and the ones of the client of the audience.
        $this->assertContains('admin', [...$user->getRoles()]);
        $this->assertContains('writer', [...$user->getRoles()]);
    }

    #[Test]
    public function theUserCanHaveAsManyTokensAsItWantsAndSeesThemAll(): void
    {
        $sid = $this->logIn();
        $first = $this->makeToken($sid);
        $second = $this->makeToken($sid);
        $third = $this->makeToken($sid);

        $tokens = $this->tokens($sid);

        $this->assertCount(3, $tokens);
        $this->assertSame(3, self::$keycloak->admin()->offlineSessions('otto', 'derafu-auth'));
        foreach ($tokens as $token) {
            $this->assertGreaterThan(time(), $token->expiresAt);
            $this->assertLessThanOrEqual(time(), $token->createdAt);
            $this->assertNotNull($token->ip);
            // What the package makes is a program: Keycloak knows no browser for it.
            $this->assertNull($token->browser);
        }
        // The session of the login is not one of them.
        $this->assertNotContains(TokenClaims::of($this->sessions->getAccessToken(new Session($this->app->persistence->store[$sid])) ?? '')['sid'], array_map(fn ($t) => $t->id, $tokens));
        foreach ([$first, $second, $third] as $token) {
            $this->assertNotNull($this->callApi($token));
        }
    }

    #[Test]
    public function aTokenIsRevokedByItselfAndTheOthersKeepWorking(): void
    {
        $sid = $this->logIn();
        $first = $this->makeToken($sid);
        $second = $this->makeToken($sid);

        $id = TokenClaims::of($first)['sid'];
        $response = $this->handle(
            $this->app->request('/auth/profile/tokens/' . $id . '/revoke', body: [], sid: $sid, headers: ['Sec-Fetch-Site' => 'same-origin']),
            fn (ServerRequestInterface $request) => $this->account->tokenRevoke($request, $id)
        );

        $this->assertSame('/auth/profile#api:tokens', $response->getHeaderLine('Location'));
        // At once: Keycloak says that its access token is not active either.
        $this->assertNull($this->callApi($first));
        $this->assertNotNull($this->callApi($second));
        $this->assertCount(1, $this->tokens($sid));
        // The session of the login goes on.
        $this->assertSame(200, $this->handle(
            $this->app->request('/auth/profile', sid: $sid),
            fn (ServerRequestInterface $request) => new HtmlResponse($this->account->profile($request))
        )->getStatusCode());
    }

    #[Test]
    public function onlyATokenOfTheUserCanBeRevoked(): void
    {
        $sid = $this->logIn();
        $session = new Session($this->app->persistence->store[$sid]);
        $loginSession = TokenClaims::of($this->sessions->getAccessToken($session) ?? '')['sid'];

        foreach ([$loginSession, 'not-a-session'] as $id) {
            $response = $this->handle(
                $this->app->request('/auth/profile/tokens/x/revoke', body: [], sid: $sid, headers: ['Sec-Fetch-Site' => 'same-origin']),
                fn (ServerRequestInterface $request) => $this->account->tokenRevoke($request, $id)
            );
            $this->assertSame('/auth/profile#api:tokens', $response->getHeaderLine('Location'));
        }

        // The login session was not revoked: the user is still logged in.
        $this->assertSame(200, $this->handle(
            $this->app->request('/auth/profile', sid: $sid),
            fn (ServerRequestInterface $request) => new HtmlResponse($this->account->profile($request))
        )->getStatusCode());
    }

    #[Test]
    public function whatChangesTokensIsOnlyForTheSiteItself(): void
    {
        $sid = $this->logIn();

        $this->expectException(AuthorizationException::class);

        $this->askForToken($sid, ['password' => 'secret'], ['Sec-Fetch-Site' => 'cross-site']);
    }

    #[Test]
    public function theProfileShowsTheDataOfKeycloakTheTokensAndTheSession(): void
    {
        $sid = $this->logIn();
        $this->makeToken($sid);

        $html = (string) $this->handle(
            $this->app->request('/auth/profile', ['tab' => 'api'], sid: $sid),
            fn (ServerRequestInterface $request) => new HtmlResponse($this->account->profile($request))
        )->getBody();

        $this->assertStringContainsString('otto@example.com', $html);
        // The example of the call to the API has the site of the redirect URI, not a host of the request.
        $this->assertStringContainsString('curl -H "Authorization: Bearer TOKEN" https://app.test/api/...', $html);
        $this->assertStringContainsString(self::$keycloak->url() . '/realms/test/account', $html);
        $this->assertStringContainsString('curl -H "Authorization: Bearer TOKEN" https://app.test/api/...', $html);
        $this->assertStringContainsString('Generar un token', $html);
        // The password is the one of the user in the realm of the site, and it says so.
        $this->assertStringContainsString('Es la contraseña del usuario <code>otto</code> en el realm <code>test</code>.', $html);
        $this->assertStringContainsString('Token de Keycloak', $html);
        $this->assertStringContainsString('Sesión en Keycloak', $html);
        $this->assertMatchesRegularExpression('#action="/auth/token/revoke/[^"]+"#', $html);
    }

    #[Test]
    public function aUserWhoseRealmDoesNotLetItManageItsSessionsGetsAPageThatSaysWhy(): void
    {
        $sid = $this->logIn();
        // Nothing to ask the account API with: the page is still there.
        $this->app->persistence->store[$sid]['oauth2_token'] = 'not-a-token';

        $html = (string) $this->handle(
            $this->app->request('/auth/profile', sid: $sid),
            fn (ServerRequestInterface $request) => new HtmlResponse($this->account->profile($request))
        )->getBody();

        $this->assertStringContainsString('otto', $html);
    }

    /**
     * The response that the API gives to a request with a token.
     */
    private function responseOf(string $token, ?AuthenticationInterface $authentication = null): ResponseInterface
    {
        return $this->app->handleAuthenticated(
            $this->app->request('/api/items', headers: ['Authorization' => 'Bearer ' . $token]),
            $authentication ?? $this->authentication,
            fn (): null => null
        );
    }

    /**
     * The authentication of an application that has no cache pool: the offline token
     * is exchanged in each request.
     */
    private function withoutCache(string $audience = 'derafu-api', bool $introspection = true): AuthenticationInterface
    {
        $config = Stack::keycloakConfiguration([
            'keycloak_url' => self::$keycloak->url(),
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'api_audience' => $audience,
            'api_client_id' => 'derafu-api',
            'api_client_secret' => 'api-secret',
            'api_introspection' => $introspection,
            'enabled' => true,
            'protected_paths' => ['/api'],
        ]);

        return Stack::keycloak(new KeycloakUserRepository($config), $config, $this->sessions);
    }

    #[Test]
    public function anOfflineTokenWhoseAccessTokenIsNotForThisApiIsRefusedAndTheClientIsToldWhy(): void
    {
        // What the realm gives when the token is exchanged has the audience of
        // `derafu-api`. An API that is another one (a client that is not in the
        // audience, as an application that has not set up the mapper of the
        // audience) must not take it, and the 401 says why.
        $token = $this->makeToken($this->logIn());

        $response = $this->responseOf($token, $this->withoutCache('derafu-noaudience', introspection: false));

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            'Bearer realm="API", error="invalid_token", error_description="The audience of the token is not this API."',
            $response->getHeaderLine('WWW-Authenticate')
        );
        // The same token, for the API that it was made for, is accepted.
        $this->assertNotNull($this->callApi($token, $this->withoutCache()));
    }

    #[Test]
    public function aRevokedOfflineTokenSaysThatKeycloakDidNotAcceptIt(): void
    {
        $sid = $this->logIn();
        $token = $this->makeToken($sid);
        $id = TokenClaims::of($token)['sid'];
        $this->handle(
            $this->app->request('/auth/profile/tokens/' . $id . '/revoke', body: [], sid: $sid, headers: ['Sec-Fetch-Site' => 'same-origin']),
            fn (ServerRequestInterface $request) => $this->account->tokenRevoke($request, $id)
        );

        $this->assertSame(
            'Bearer realm="API", error="invalid_token", error_description="Keycloak did not accept the offline token."',
            $this->responseOf($token, $this->withoutCache())->getHeaderLine('WWW-Authenticate')
        );
    }

    #[Test]
    public function theTokenWorksWithoutACachePool(): void
    {
        $token = $this->makeToken($this->logIn());

        $this->assertNotNull($this->callApi($token, $this->withoutCache()));
    }

    #[Test]
    public function theRolesAreTheOnesThatKeycloakGivesWhenTheTokenIsExchanged(): void
    {
        $token = $this->makeToken($this->logIn());
        $authentication = $this->withoutCache();
        $this->assertNotContains('editor', [...($this->callApi($token, $authentication)?->getRoles() ?? [])]);

        // A role that the administrator gives is in the next request: the token is
        // not regenerated.
        self::$keycloak->admin()->addRealmRole('otto', 'editor');

        $this->assertContains('editor', [...($this->callApi($token, $authentication)?->getRoles() ?? [])]);
    }

    #[Test]
    public function aTokenStopsWorkingWhenItsUserIsDisabled(): void
    {
        $token = $this->makeToken($this->logIn());
        $this->assertNotNull($this->callApi($token));

        self::$keycloak->admin()->setEnabled('otto', false);

        $this->assertNull($this->callApi($token));
        $this->assertNull($this->callApi($token, $this->withoutCache()));
    }

    #[Test]
    public function anOfflineTokenThatAnotherClientMadeIsRefused(): void
    {
        // The client `derafu-cli` of the realm lets a person ask for its own token;
        // Keycloak does not let the client of this application exchange it.
        $answer = (new \Derafu\TestsAuth\Fixture\KeycloakTokens(self::$keycloak->url()))
            ->person('derafu-cli', 'otto', 'secret', 'openid offline_access');
        $this->assertTrue(TokenClaims::isOffline((string) $answer['refresh_token']));

        $this->assertNull($this->callApi((string) $answer['refresh_token']));
        $this->assertNull($this->callApi((string) $answer['refresh_token'], $this->withoutCache()));
    }

    #[Test]
    public function aTextThatOnlySaysThatItIsAnOfflineTokenIsRefused(): void
    {
        $encode = static fn (array $data): string => rtrim(strtr(base64_encode((string) json_encode($data)), '+/', '-_'), '=');
        $forged = $encode(['alg' => 'HS512']) . '.' . $encode(['typ' => 'Offline', 'sub' => 'x']) . '.signature';

        $this->assertNull($this->callApi($forged));
    }
}
