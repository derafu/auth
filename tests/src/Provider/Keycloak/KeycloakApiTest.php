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

use Derafu\Auth\Authorization;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Provider\Keycloak\KeycloakAuthentication;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\TestsAuth\Fixture\KeycloakTokens;
use Derafu\TestsAuth\Fixture\RealKeycloak;
use Derafu\TestsAuth\Fixture\SessionApp;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A client of the API that sends the token that a real Keycloak gave it, the way
 * a program gets one: a service with its client and its secret, or a person that
 * gives its password. The realm has the client of the API (`derafu-api`, the
 * audience) and the clients that call it: the one of a service, the one of a person,
 * and one whose tokens are not for the API.
 */
#[CoversClass(KeycloakAuthentication::class)]
#[CoversClass(KeycloakUserRepository::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authorization::class)]
#[UsesClass(\Derafu\Auth\Exception\AuthenticationException::class)]
#[UsesClass(\Derafu\Auth\Exception\ProviderUnavailableException::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(KeycloakSessionManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier::class)]
#[UsesClass(\Derafu\Auth\SessionManager::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
final class KeycloakApiTest extends TestCase
{
    private static RealKeycloak $keycloak;

    private static KeycloakTokens $tokens;

    private SessionApp $app;

    public static function setUpBeforeClass(): void
    {
        self::$keycloak = RealKeycloak::start();
        self::$tokens = new KeycloakTokens(self::$keycloak->url());
    }

    public static function tearDownAfterClass(): void
    {
        self::$keycloak->stop();
    }

    protected function setUp(): void
    {
        $this->app = new SessionApp();
    }

    protected function tearDown(): void
    {
        self::$keycloak->admin()->reset();
    }

    /**
     * The API: the client of the audience, `derafu-api`, is the client of the
     * configuration.
     *
     * @param array<string, mixed> $config
     */
    private function api(array $config = []): AuthenticationInterface
    {
        $config = new KeycloakConfiguration($config + [
            'keycloak_url' => self::$keycloak->url(),
            'realm' => 'test',
            'client_id' => 'derafu-api',
            'client_secret' => 'api-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'enabled' => true,
            'protected_paths' => ['/api'],
        ]);

        return new KeycloakAuthentication(
            new KeycloakUserRepository($config),
            $config,
            new KeycloakSessionManager()
        );
    }

    /**
     * @return array{response: ResponseInterface, user: mixed}
     */
    private function call(AuthenticationInterface $authentication, string $token, string $path = '/api/items'): array
    {
        $user = null;
        $response = $this->app->handleAuthenticated(
            $this->app->request($path, headers: ['Authorization' => 'Bearer ' . $token]),
            $authentication,
            function (ServerRequestInterface $request) use (&$user): null {
                $user = $request->getAttribute(MezzioUserInterface::class);

                return null;
            }
        );

        return ['response' => $response, 'user' => $user];
    }

    private function serviceToken(): string
    {
        return (string) self::$tokens->service('derafu-service', 'service-secret')['access_token'];
    }

    // -------------------------------------------------------------------------
    // The token of a service, and the token of a person.
    // -------------------------------------------------------------------------

    #[Test]
    public function aServiceThatAskedForItsTokenWithItsClientAndItsSecretIsAuthenticated(): void
    {
        $result = $this->call($this->api(), $this->serviceToken());

        $this->assertSame(200, $result['response']->getStatusCode());
        $this->assertInstanceOf(MezzioUserInterface::class, $result['user']);
        $this->assertSame('service-account-derafu-service', $result['user']->getDetail('preferred_username'));
        // The roles of its user in the realm, and the ones of the client of the API.
        $this->assertEqualsCanonicalizing(['editor', 'reader'], $result['user']->getRoles());
    }

    #[Test]
    public function aPersonThatGaveItsPasswordToAClientIsAuthenticatedWithItsOwnRoles(): void
    {
        $token = (string) self::$tokens->person('derafu-cli', 'ana', 'secret')['access_token'];

        $result = $this->call($this->api(), $token);

        $this->assertSame('ana', $result['user']?->getDetail('preferred_username'));
        $this->assertSame('ana@example.com', $result['user']->getEmail());
        // `admin` of the realm and `writer` of the API: not what ana can do in the
        // client of the application (`app-editor`), that is not this API.
        $this->assertEqualsCanonicalizing(['admin', 'writer'], $result['user']->getRoles());
    }

    #[Test]
    public function aPersonAndAServiceAreTheSameKindOfClientForTheApi(): void
    {
        $authentication = $this->api();
        $person = $this->call($authentication, (string) self::$tokens->person('derafu-cli', 'ana', 'secret')['access_token']);
        $service = $this->call($authentication, $this->serviceToken());

        $this->assertSame(200, $person['response']->getStatusCode());
        $this->assertSame(200, $service['response']->getStatusCode());
        $this->assertNotSame($person['user']?->getIdentity(), $service['user']?->getIdentity());
    }

    #[Test]
    public function aClientDoesNotKeepASession(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = ['unrelated' => 'data'];
        $before = $this->app->persistence->store;

        $this->call($this->api(), $this->serviceToken());

        $this->assertSame($before, $this->app->persistence->store);
    }

    #[Test]
    public function theRolesOfTheUserDecideWhatThePathNeeds(): void
    {
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::$keycloak->url(),
            'client_id' => 'derafu-api',
            'enabled' => true,
            'protected_paths' => ['/api', '/api/admin' => ['admin'], '/api/data' => ['reader', 'writer']],
        ]);
        $authentication = $this->api(['protected_paths' => ['/api', '/api/admin' => ['admin'], '/api/data' => ['reader', 'writer']]]);
        $authorization = new Authorization($config);

        // A service has `editor` and `reader`: it reads the data, it is not an admin.
        $service = $this->call($authentication, $this->serviceToken())['user'];
        $this->assertNotNull($service);
        $this->assertFalse($authorization->isGrantedAny(['admin'], $this->app->request('/api/admin/x')->withAttribute(MezzioUserInterface::class, $service)));
        $this->assertTrue($authorization->isGrantedAny(['reader', 'writer'], $this->app->request('/api/data')->withAttribute(MezzioUserInterface::class, $service)));

        // Ana is an admin.
        $ana = $this->call($authentication, (string) self::$tokens->person('derafu-cli', 'ana', 'secret')['access_token'])['user'];
        $this->assertNotNull($ana);
        $this->assertTrue($authorization->isGrantedAny(['admin'], $this->app->request('/api/admin/x')->withAttribute(MezzioUserInterface::class, $ana)));
    }

    // -------------------------------------------------------------------------
    // The tokens that are not for the API.
    // -------------------------------------------------------------------------

    #[Test]
    public function aTokenThatKeycloakDidNotMakeForTheApiIsNotAuthenticated(): void
    {
        // A valid token of the realm, of a client that is not for the API (the
        // audience is what says it).
        $token = (string) self::$tokens->service('derafu-noaudience', 'noaudience-secret')['access_token'];

        $result = $this->call($this->api(), $token);

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
        $this->assertSame('Bearer realm="API", error="invalid_token"', $result['response']->getHeaderLine('WWW-Authenticate'));
    }

    #[Test]
    public function theIdTokenAndTheRefreshTokenAreNotAccessTokens(): void
    {
        $answer = self::$tokens->person('derafu-cli', 'ana', 'secret');

        // The ID token of the login of a client has the audience of that client: it
        // must not open the API of a client that is the same.
        $api = $this->api(['client_id' => 'derafu-cli', 'client_secret' => '', 'api_audience' => 'derafu-cli']);

        $this->assertNull($this->call($api, (string) $answer['id_token'])['user']);
        $this->assertNull($this->call($this->api(), (string) $answer['refresh_token'])['user']);
        $this->assertNull($this->call($this->api(), (string) $answer['id_token'])['user']);
    }

    // -------------------------------------------------------------------------
    // Keycloak is asked whether the token is active.
    // -------------------------------------------------------------------------

    #[Test]
    public function aUserThatWasDisabledLosesTheAccessAtOnceWithoutWaitingForTheTokenToExpire(): void
    {
        $token = (string) self::$tokens->person('derafu-cli', 'ana', 'secret')['access_token'];
        $authentication = $this->api();
        $before = $this->call($authentication, $token);
        $this->assertNotNull($before['user']);

        self::$keycloak->admin()->setEnabled('ana', false);

        // The token was not revoked and has not expired, and it is not valid.
        $result = $this->call($authentication, $token);
        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
    }

    #[Test]
    public function aUserWhoseSessionsEndedLosesTheAccessAtOnce(): void
    {
        $token = (string) self::$tokens->person('derafu-cli', 'ana', 'secret')['access_token'];
        $authentication = $this->api();
        $before = $this->call($authentication, $token);
        $this->assertNotNull($before['user']);

        self::$keycloak->admin()->logOut('ana');

        $after = $this->call($authentication, $token);
        $this->assertNull($after['user']);
    }

    #[Test]
    public function withTheIntrospectionOffTheTokenOfADisabledUserIsValidUntilItExpires(): void
    {
        // What it costs not to ask: the token is verified by what it says. It is
        // for the clients whose tokens last a short time.
        $token = (string) self::$tokens->person('derafu-cli', 'ana', 'secret')['access_token'];
        $authentication = $this->api(['api_introspection' => false]);

        self::$keycloak->admin()->setEnabled('ana', false);

        $this->assertNotNull($this->call($authentication, $token)['user']);
    }

    #[Test]
    public function aKeycloakThatDoesNotAnswerIsNotAWayIn(): void
    {
        $token = $this->serviceToken();
        $authentication = $this->api(['http_client_options' => ['timeout' => 2, 'connect_timeout' => 2]]);

        self::$keycloak->pause();
        try {
            $result = $this->call($authentication, $token);
        } finally {
            self::$keycloak->unpause();
        }

        // Not an error of the server: the same answer as a request that is not
        // authenticated, because it can not be told that it is.
        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
    }

    #[Test]
    public function anApplicationThatHasTheLoginAndTheApiInOneClientAuthenticatesTheTokensThatHaveItInTheirAudience(): void
    {
        // One client for the web login and the API: the token of a person that
        // has its roles in it has it in its audience, and Keycloak answers for it.
        $token = (string) self::$tokens->person('derafu-cli', 'ana', 'secret')['access_token'];
        $authentication = $this->api(['client_id' => 'derafu-auth', 'client_secret' => 'test-secret']);

        $result = $this->call($authentication, $token);

        $this->assertSame(200, $result['response']->getStatusCode());
        // The roles of the realm and the ones of this client.
        $this->assertEqualsCanonicalizing(['admin', 'app-editor'], $result['user']?->getRoles());
    }

    #[Test]
    public function keycloakSaysThatATokenIsNotActiveToAClientThatIsNotInItsAudience(): void
    {
        // What the configuration refuses to have (an audience that is not the
        // client, with the introspection on) is what Keycloak does: the same token
        // that the client of the API finds active, the application does not.
        $token = $this->serviceToken();

        $this->assertNotNull($this->call($this->api(), $token)['user']);
        $this->assertNull($this->call($this->api(['client_id' => 'derafu-auth', 'client_secret' => 'test-secret']), $token)['user']);
    }

    #[Test]
    public function theCredentialsOfAClientThatKeycloakDoesNotAcceptAreNotWhatMakesATokenNotValid(): void
    {
        $authentication = $this->api(['client_secret' => 'a-wrong-secret']);

        // The token is the right one; it is the client of the application that is
        // not accepted. It is a misconfiguration, and nobody is let in because of it.
        $this->assertNull($this->call($authentication, $this->serviceToken())['user']);
    }

    #[Test]
    public function theApiCanBeAClientOfItsOwnApartFromTheClientOfTheLogin(): void
    {
        // The application logs in with its client, and the API asks Keycloak about
        // the tokens with the client of the API, that is the audience of the tokens.
        $authentication = $this->api([
            'client_id' => 'derafu-auth',
            'client_secret' => 'test-secret',
            'api_client_id' => 'derafu-api',
            'api_client_secret' => 'api-secret',
        ]);

        $result = $this->call($authentication, $this->serviceToken());

        $this->assertSame(200, $result['response']->getStatusCode());
        $this->assertNotNull($result['user']);
    }

    #[Test]
    public function theSecretOfTheClientOfTheApiIsTheOneThatKeycloakIsAskedWith(): void
    {
        // The client of the login has a good secret: it is the one of the API that
        // is wrong, so nobody is let in.
        $authentication = $this->api([
            'client_id' => 'derafu-auth',
            'client_secret' => 'test-secret',
            'api_client_id' => 'derafu-api',
            'api_client_secret' => 'a-wrong-secret',
        ]);

        $this->assertNull($this->call($authentication, $this->serviceToken())['user']);
    }
}
