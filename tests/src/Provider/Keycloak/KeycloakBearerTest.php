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

use ArrayObject;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * A client of the API that sends the access token that Keycloak gave it
 * (`Bearer`): what is verified in the token, with tokens made for the test and
 * the keys of a realm that is not real, so every way in which a token can be
 * wrong is tried (the real realm is in `KeycloakApiTest`).
 */
#[CoversClass(KeycloakWebFlow::class)]
#[CoversClass(KeycloakTokenVerifier::class)]
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
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authorization\AuthorizationManager::class)]
#[UsesClass(\Derafu\Auth\Exception\AuthenticationException::class)]
#[UsesClass(\Derafu\Auth\Exception\ConfigurationException::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(KeycloakSessionManager::class)]
#[UsesClass(KeycloakUserRepository::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\SessionManager::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationMiddleware::class)]
final class KeycloakBearerTest extends TestCase
{
    private const URL = 'https://keycloak.test';

    private const ISSUER = 'https://keycloak.test/realms/test';

    private static string $pem;

    private static string $publicPem;

    private static string $jwks;

    private SessionApp $app;

    private FixedKeysClient $http;

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        openssl_pkey_export($key, $pem);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);

        self::$pem = $pem;
        self::$publicPem = $details['key'];

        $base64 = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        self::$jwks = (string) json_encode(['keys' => [[
            'kid' => 'the-key',
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => $base64($details['rsa']['n']),
            'e' => $base64($details['rsa']['e']),
        ]]]);
    }

    protected function setUp(): void
    {
        $this->app = new SessionApp();
        $this->http = new FixedKeysClient(self::$jwks);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function authentication(array $config = [], ?ArrayAdapter $cache = null, ?GuzzleClient $keycloak = null): AuthenticationInterface
    {
        $config = Stack::keycloakConfiguration($config + [
            'keycloak_url' => self::URL,
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'a-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'api_audience' => 'derafu-api',
            // The realm is not real: what is asked to it is tried below, with a
            // client that answers what the test says.
            'api_introspection' => false,
            'enabled' => true,
            'protected_paths' => ['/api', '/private'],
        ]);

        return Stack::keycloak(
            new KeycloakUserRepository(
                $config,
                new KeycloakTokenVerifier($config, $cache, $this->http, new HttpFactory()),
                httpClient: $keycloak
            ),
            $config,
            new KeycloakSessionManager()
        );
    }

    /**
     * A token as Keycloak makes an access token, with what is changed.
     *
     * @param array<string, mixed> $claims What is added or replaced (`null` removes it).
     */
    private function token(array $claims = [], string $algorithm = 'RS256', ?string $key = null, string $kid = 'the-key'): string
    {
        $claims = $claims + [
            'iss' => self::ISSUER,
            'sub' => 'user-1',
            'aud' => ['derafu-api', 'account'],
            'typ' => 'Bearer',
            'azp' => 'a-service',
            'iat' => time(),
            'exp' => time() + 300,
            'preferred_username' => 'service-account-a-service',
            'realm_access' => ['roles' => ['editor']],
            'resource_access' => [
                'derafu-api' => ['roles' => ['reader']],
                'another-client' => ['roles' => ['evil']],
            ],
        ];

        return JWT::encode(array_filter($claims, static fn (mixed $value): bool => $value !== null), $key ?? self::$pem, $algorithm, $kid);
    }

    /**
     * @param array<string, string> $headers
     * @return array{response: ResponseInterface, user: mixed}
     */
    private function call(AuthenticationInterface $authentication, array $headers = [], string $path = '/api/items'): array
    {
        $user = null;
        $response = $this->app->handleAuthenticated(
            $this->app->request($path, headers: $headers),
            $authentication,
            function (ServerRequestInterface $request) use (&$user): null {
                $user = $request->getAttribute(MezzioUserInterface::class);

                return null;
            }
        );

        return ['response' => $response, 'user' => $user];
    }

    /**
     * @return array<string, string>
     */
    private function bearer(string $token, string $scheme = 'Bearer'): array
    {
        return ['Authorization' => $scheme . ' ' . $token];
    }

    // -------------------------------------------------------------------------
    // A token that is valid.
    // -------------------------------------------------------------------------

    #[Test]
    public function aClientThatSendsAnAccessTokenWithTheAudienceIsAuthenticated(): void
    {
        $result = $this->call($this->authentication(), $this->bearer($this->token()));

        $this->assertSame(200, $result['response']->getStatusCode());
        $this->assertInstanceOf(MezzioUserInterface::class, $result['user']);
        $this->assertSame('user-1', $result['user']->getIdentity());
        $this->assertSame('service-account-a-service', $result['user']->getDetail('preferred_username'));
    }

    #[Test]
    public function theRolesAreTheOnesOfTheRealmAndTheOnesOfTheClientOfTheAudience(): void
    {
        $user = $this->call($this->authentication(), $this->bearer($this->token()))['user'];

        // What the user can do in another client says nothing about this API.
        $this->assertEqualsCanonicalizing(['editor', 'reader'], $user?->getRoles());
    }

    #[Test]
    public function theClientOfTheAudienceIsTheOneThatIsConfiguredNotTheOneOfTheApplication(): void
    {
        $token = $this->token([
            'aud' => ['billing-api'],
            'resource_access' => [
                'billing-api' => ['roles' => ['biller']],
                'derafu-auth' => ['roles' => ['app-editor']],
            ],
        ]);

        $user = $this->call($this->authentication(['api_audience' => 'billing-api']), $this->bearer($token))['user'];

        $this->assertEqualsCanonicalizing(['editor', 'biller'], $user?->getRoles());
    }

    #[Test]
    public function withoutAConfiguredAudienceTheAudienceIsTheClientOfTheApplication(): void
    {
        $authentication = $this->authentication(['api_audience' => '']);

        $this->assertNull($this->call($authentication, $this->bearer($this->token()))['user']);
        $this->assertNotNull($this->call($authentication, $this->bearer($this->token(['aud' => ['derafu-auth']])))['user']);
    }

    #[Test]
    public function theClientThatAskedForTheTokenIsNotRestricted(): void
    {
        // Any client of the realm can call the API if Keycloak made its token for
        // it (the audience): it is the realm that decides who is let in.
        foreach (['a-service', 'derafu-cli', 'another-client'] as $client) {
            $this->assertNotNull($this->call($this->authentication(), $this->bearer($this->token(['azp' => $client])))['user'], $client);
        }
        $this->assertNotNull($this->call($this->authentication(), $this->bearer($this->token(['azp' => null])))['user']);
    }

    #[Test]
    public function theSchemeDoesNotDependOnItsCase(): void
    {
        foreach (['Bearer', 'bearer', 'BEARER'] as $scheme) {
            $this->assertNotNull($this->call($this->authentication(), $this->bearer($this->token(), $scheme))['user'], $scheme);
        }
    }

    #[Test]
    public function aClientOfTheApiDoesNotKeepASession(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = ['unrelated' => 'data'];
        $before = $this->app->persistence->store;

        $this->call($this->authentication(), $this->bearer($this->token()));

        $this->assertSame($before, $this->app->persistence->store);
    }

    // -------------------------------------------------------------------------
    // A token that is not valid.
    // -------------------------------------------------------------------------

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function provideClaimsThatAreNotValid(): array
    {
        return [
            'expired, past the margin of the clocks' => [['exp' => time() - 300]],
            'not valid yet' => [['nbf' => time() + 300]],
            'from another realm' => [['iss' => 'https://keycloak.test/realms/other']],
            'from another server' => [['iss' => 'https://evil.test/realms/test']],
            'without an issuer' => [['iss' => null]],
            'an ID token' => [['typ' => 'ID']],
            'a refresh token' => [['typ' => 'Refresh']],
            'an offline token' => [['typ' => 'Offline']],
            'a token without type' => [['typ' => null]],
            'a type that is not the one of Keycloak' => [['typ' => 'bearer']],
            'without an audience' => [['aud' => null]],
            'with the audience of another API' => [['aud' => ['another-api']]],
            'with the audience of another API, as text' => [['aud' => 'another-api']],
            'with only the default audience of Keycloak' => [['aud' => ['account']]],
            'with an empty audience' => [['aud' => []]],
            'with an audience that only looks alike' => [['aud' => ['derafu-api-extra', 'derafu']]],
            'without a user' => [['sub' => null]],
        ];
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[Test]
    #[DataProvider('provideClaimsThatAreNotValid')]
    public function aTokenThatIsNotValidIsNotAuthenticated(array $claims): void
    {
        $result = $this->call($this->authentication(), $this->bearer($this->token($claims)));

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
        $this->assertSame('Bearer realm="API", error="invalid_token"', $result['response']->getHeaderLine('WWW-Authenticate'));
    }

    #[Test]
    public function theExpirationIsCheckedWhenTheTokenHasOneAndIsNotRequired(): void
    {
        // A token that does not say when it expires, like one that was made to
        // last, is valid; one that says it and it is over is not (the margin of
        // the clocks is one minute).
        $this->assertNotNull($this->call($this->authentication(), $this->bearer($this->token(['exp' => null])))['user']);
        $this->assertNotNull($this->call($this->authentication(), $this->bearer($this->token(['exp' => time() + 100 * 365 * 86400])))['user']);
        $this->assertNotNull($this->call($this->authentication(), $this->bearer($this->token(['exp' => time() - 30])))['user']);
        $this->assertNull($this->call($this->authentication(), $this->bearer($this->token(['exp' => time() - 120])))['user']);
    }

    #[Test]
    public function thereCanBeSeveralPathsOfTheApi(): void
    {
        $authentication = $this->authentication(['api_paths' => ['/api', '/docs/index.json'], 'protected_paths' => ['/api', '/docs']]);

        foreach (['/api/items', '/docs/index.json', '/docs/index.json/x'] as $path) {
            $this->assertNotNull($this->call($authentication, $this->bearer($this->token()), $path)['user'], $path);
        }

        $result = $this->call($authentication, $this->bearer($this->token()), '/docs/other');
        $this->assertNull($result['user']);
        $this->assertSame(302, $result['response']->getStatusCode());
    }

    #[Test]
    public function theAudienceAsATextIsValidToo(): void
    {
        $this->assertNotNull($this->call($this->authentication(), $this->bearer($this->token(['aud' => 'derafu-api'])))['user']);
    }

    #[Test]
    public function aTokenThatIsNotSignedByTheRealmIsNotAuthenticated(): void
    {
        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($other);
        openssl_pkey_export($other, $otherPem);

        $tokens = [
            'another key with the id of the realm' => $this->token(key: $otherPem),
            'a key id that the realm does not have' => $this->token(kid: 'another-key'),
            'a token whose algorithm is HS256 and whose secret is the public key' => $this->token(algorithm: 'HS256', key: self::$publicPem),
            'a token without signature' => $this->unsigned(),
        ];

        foreach ($tokens as $name => $token) {
            $result = $this->call($this->authentication(), $this->bearer($token));

            $this->assertNull($result['user'], $name);
            $this->assertSame(401, $result['response']->getStatusCode(), $name);
        }
    }

    #[Test]
    public function aTokenWhoseContentWasChangedIsNotAuthenticated(): void
    {
        // The signature is the one of another token: what the token says is what
        // an attacker wants it to say.
        [$header, , $signature] = explode('.', $this->token());
        $payload = rtrim(strtr(base64_encode((string) json_encode([
            'iss' => self::ISSUER,
            'sub' => 'the-admin',
            'aud' => ['derafu-api'],
            'typ' => 'Bearer',
            'exp' => time() + 300,
            'realm_access' => ['roles' => ['admin']],
        ])), '+/', '-_'), '=');

        $result = $this->call($this->authentication(), $this->bearer($header . '.' . $payload . '.' . $signature));

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function provideTextsThatAreNotTokens(): array
    {
        // The text, and whether the realm is not even asked for its keys: it is
        // not when the text does not have the three segments of a token.
        return [
            'one word' => ['abc', false],
            'two segments' => ['abc.def', false],
            'four segments' => ['a.b.c.d', false],
            'three segments of nothing' => ['a.b.c', true],
            'three empty segments' => ['..', true],
            'not base64' => ['!!!.!!!.!!!', true],
        ];
    }

    #[Test]
    #[DataProvider('provideTextsThatAreNotTokens')]
    public function whatIsNotATokenIsNotAuthenticated(string $text, bool $asksForTheKeys): void
    {
        $result = $this->call($this->authentication(), $this->bearer($text));

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());

        // What is not worth the keys of the realm does not ask for them.
        if (!$asksForTheKeys) {
            $this->assertSame(0, $this->http->requests);
        }
    }

    private function unsigned(): string
    {
        $part = static fn (array $data): string => rtrim(strtr(base64_encode((string) json_encode($data)), '+/', '-_'), '=');

        return $part(['alg' => 'none', 'typ' => 'JWT', 'kid' => 'the-key'])
            . '.' . $part(['iss' => self::ISSUER, 'sub' => 'user-1', 'aud' => ['derafu-api'], 'typ' => 'Bearer', 'exp' => time() + 300])
            . '.';
    }

    // -------------------------------------------------------------------------
    // The answer of the API.
    // -------------------------------------------------------------------------

    #[Test]
    public function aRequestWithoutATokenIsToldHowToAuthenticateWithoutAnError(): void
    {
        $response = $this->call($this->authentication())['response'];

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
        // RFC 6750: no error when the client did not send credentials.
        $this->assertSame('Bearer realm="API"', $response->getHeaderLine('WWW-Authenticate'));
    }

    #[Test]
    public function theChallengeOfBearerIsSentToAScriptToo(): void
    {
        // A browser does not open a window for Bearer, so nothing is left out.
        $response = $this->call($this->authentication(), ['X-Requested-With' => 'XMLHttpRequest'])['response'];

        $this->assertSame('Bearer realm="API"', $response->getHeaderLine('WWW-Authenticate'));
    }

    #[Test]
    public function aHeaderOfAnotherSchemeIsNotCredentialsForThisProvider(): void
    {
        $response = $this->call($this->authentication(), ['Authorization' => 'Basic ' . base64_encode('ana:secret')])['response'];

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Bearer realm="API"', $response->getHeaderLine('WWW-Authenticate'));
    }

    #[Test]
    public function theRealmOfTheChallengeAndThePathOfTheApiAreConfigurable(): void
    {
        $authentication = $this->authentication(['api_realm' => 'Billing', 'api_paths' => ['/v1'], 'protected_paths' => ['/v1']]);

        $this->assertSame('Bearer realm="Billing"', $this->call($authentication, [], '/v1/invoices')['response']->getHeaderLine('WWW-Authenticate'));
        $this->assertNotNull($this->call($authentication, $this->bearer($this->token()), '/v1/invoices')['user']);

        // /api is not the API now: the token is not read there, the user is the
        // anonymous one of a path that is not protected.
        $this->assertTrue($this->call($authentication, $this->bearer($this->token()), '/api/items')['user']?->isAnonymous());
    }

    #[Test]
    public function theTokenIsOnlyReadInTheApi(): void
    {
        // In a page a valid token is not a user: the page is for a session.
        $result = $this->call($this->authentication(), $this->bearer($this->token()), '/private/page');

        $this->assertNull($result['user']);
        $this->assertSame(302, $result['response']->getStatusCode());
        $this->assertSame(0, $this->http->requests);
    }

    // -------------------------------------------------------------------------
    // Asking Keycloak whether the token is active (introspection).
    // -------------------------------------------------------------------------

    /**
     * A client for Keycloak that answers what it is told, in order, and keeps
     * what it was asked.
     *
     * @param list<Psr7Response|\Throwable> $answers
     * @param ArrayObject<int, array<mixed>>|null $history
     * Where what was asked is kept.
     */
    private function keycloak(array $answers, ?ArrayObject $history = null): GuzzleClient
    {
        $stack = HandlerStack::create(new MockHandler($answers));
        if ($history !== null) {
            $stack->push(Middleware::history($history));
        }

        return new GuzzleClient(['handler' => $stack]);
    }

    /**
     * @return ArrayObject<int, array<mixed>>
     */
    private function history(): ArrayObject
    {
        return new ArrayObject();
    }

    private function active(bool $active = true, ?string $sub = null): Psr7Response
    {
        return new Psr7Response(200, ['Content-Type' => 'application/json'], (string) json_encode(
            ['active' => $active] + ($sub !== null ? ['sub' => $sub] : [])
        ));
    }

    /**
     * @param array<string, mixed> $config
     */
    private function withIntrospection(GuzzleClient $keycloak, array $config = []): AuthenticationInterface
    {
        // Keycloak is asked by the client, so the audience is the client.
        return $this->authentication(
            $config + ['api_introspection' => true, 'client_id' => 'derafu-api', 'api_audience' => ''],
            keycloak: $keycloak
        );
    }

    #[Test]
    public function keycloakIsAskedWithTheClientOfTheApiWhenItHasItsOwn(): void
    {
        $history = $this->history();
        $authentication = $this->withIntrospection(
            $this->keycloak([$this->active(true, 'user-1')], $history),
            ['api_client_id' => 'derafu-billing', 'api_client_secret' => 'billing-secret', 'client_id' => 'derafu-web']
        );

        $result = $this->call($authentication, $this->bearer($this->token(['aud' => ['derafu-billing']])));

        $this->assertSame('user-1', $result['user']?->getIdentity());
        $request = $history[0]['request'];
        $this->assertInstanceOf(RequestInterface::class, $request);
        parse_str((string) $request->getBody(), $form);
        $this->assertSame('derafu-billing', $form['client_id']);
        $this->assertSame('billing-secret', $form['client_secret']);
    }

    #[Test]
    public function keycloakIsAskedWhetherTheTokenIsActiveByDefault(): void
    {
        $history = $this->history();
        $authentication = $this->withIntrospection($this->keycloak([$this->active(true, 'user-1')], $history));

        $result = $this->call($authentication, $this->bearer($this->token()));

        $this->assertSame('user-1', $result['user']?->getIdentity());
        $this->assertCount(1, $history);

        $request = $history[0]['request'];
        $this->assertInstanceOf(RequestInterface::class, $request);
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame(self::ISSUER . '/protocol/openid-connect/token/introspect', (string) $request->getUri());
        parse_str((string) $request->getBody(), $form);
        $this->assertSame('access_token', $form['token_type_hint']);
        $this->assertStringStartsWith('eyJ', $form['token']);
        // The client of the application authenticates with its credentials.
        $this->assertSame('derafu-api', $form['client_id']);
        $this->assertSame('a-secret', $form['client_secret']);
    }

    #[Test]
    public function theIntrospectionIsOnWhenTheConfigurationDoesNotSayOtherwise(): void
    {
        $config = Stack::keycloakConfiguration([
            'keycloak_url' => self::URL,
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'a-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
        ]);

        $this->assertTrue($config->isApiIntrospection());
        $this->assertFalse((Stack::keycloakConfiguration(['api_introspection' => false]))->isApiIntrospection());
    }

    #[Test]
    public function anAudienceThatIsNotTheClientIsAnErrorOfTheConfigurationWhenKeycloakIsAsked(): void
    {
        // Keycloak says that a token is not active to every client but the ones of
        // its audience: it would close the API without a reason that shows.
        try {
            Stack::keycloakConfiguration([
                'keycloak_url' => self::URL,
                'client_id' => 'derafu-auth',
                'client_secret' => 'a-secret',
                'api_audience' => 'derafu-api',
            ])->validateApi();
            $this->fail('The configuration was accepted.');
        } catch (\Derafu\Auth\Exception\ConfigurationException $e) {
            $this->assertStringContainsString('"derafu-api"', $e->getMessage());
            $this->assertStringContainsString('"derafu-auth"', $e->getMessage());
        }

        // It is fine with the introspection off, or when the audience is the client.
        foreach ([
            ['client_id' => 'derafu-auth', 'api_audience' => 'derafu-api', 'api_introspection' => false],
            ['client_id' => 'derafu-api', 'api_audience' => 'derafu-api'],
            ['client_id' => 'derafu-api'],
        ] as $case) {
            $config = Stack::keycloakConfiguration($case + ['keycloak_url' => self::URL, 'client_secret' => 'a-secret']);
            $config->validateApi();
            $this->assertSame('derafu-api', $config->getApiAudience());
        }
    }

    #[Test]
    public function aTokenThatKeycloakDoesNotConsiderActiveIsNotAuthenticatedEvenIfItIsOtherwiseValid(): void
    {
        // It was revoked, or its user was disabled, or its session ended: what the
        // token says is still right, and Keycloak says no.
        $authentication = $this->withIntrospection($this->keycloak([$this->active(false)]));

        $result = $this->call($authentication, $this->bearer($this->token()));

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
        $this->assertSame('Bearer realm="API", error="invalid_token"', $result['response']->getHeaderLine('WWW-Authenticate'));
    }

    #[Test]
    public function theTokenOfAnotherUserThanTheOneThatKeycloakSaysIsNotAuthenticated(): void
    {
        $authentication = $this->withIntrospection($this->keycloak([$this->active(true, 'someone-else')]));

        $this->assertNull($this->call($authentication, $this->bearer($this->token()))['user']);
    }

    /**
     * @return array<string, array{callable(): (Psr7Response|ConnectException)}>
     */
    public static function provideAnswersOfKeycloakThatSayNothing(): array
    {
        return [
            'an error of the server' => [fn () => new Psr7Response(500, [], 'Internal Server Error')],
            'it does not accept the credentials of the client' => [fn () => new Psr7Response(401, [], '{"error":"unauthorized_client"}')],
            'it does not allow it' => [fn () => new Psr7Response(403, [], '{}')],
            'not a JSON' => [fn () => new Psr7Response(200, [], 'not a json')],
            'a JSON that is not an answer' => [fn () => new Psr7Response(200, [], '"yes"')],
            'without the field that says it' => [fn () => new Psr7Response(200, [], '{}')],
            'active that is not true' => [fn () => new Psr7Response(200, [], '{"active":"true"}')],
            'it does not answer' => [fn () => new ConnectException('Connection refused', new Request('POST', 'https://keycloak.test'))],
        ];
    }

    /**
     * @param callable(): (Psr7Response|\Throwable) $answer
     */
    #[Test]
    #[DataProvider('provideAnswersOfKeycloakThatSayNothing')]
    public function aTokenIsNotAcceptedWithoutKnowingThatItIsActive(callable $answer): void
    {
        // It is not a token that is not valid, but it is not let in either: the
        // answer of the API is the one of a request that is not authenticated.
        $authentication = $this->withIntrospection($this->keycloak([$answer()]));

        $result = $this->call($authentication, $this->bearer($this->token()));

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
    }

    #[Test]
    public function keycloakIsAskedInEveryRequest(): void
    {
        $history = $this->history();
        $authentication = $this->withIntrospection(
            $this->keycloak([$this->active(), $this->active(false), $this->active()], $history)
        );
        $header = $this->bearer($this->token());

        // The same token: what Keycloak says now is what counts.
        $this->assertNotNull($this->call($authentication, $header)['user']);
        $this->assertNull($this->call($authentication, $header)['user']);
        $this->assertNotNull($this->call($authentication, $header)['user']);
        $this->assertCount(3, $history);
    }

    #[Test]
    public function aTokenThatIsNotValidDoesNotCostARequestToKeycloak(): void
    {
        $history = $this->history();
        $authentication = $this->withIntrospection($this->keycloak([$this->active()], $history));

        foreach ([$this->token(['aud' => ['another-api']]), $this->token(['exp' => time() - 300]), $this->token(['typ' => 'ID']), 'not-a-token'] as $token) {
            $this->assertNull($this->call($authentication, $this->bearer($token))['user']);
        }

        $this->assertCount(0, $history);
    }

    #[Test]
    public function withTheIntrospectionOffKeycloakIsNotAsked(): void
    {
        $history = $this->history();
        $authentication = $this->authentication(['api_introspection' => false], keycloak: $this->keycloak([$this->active(false)], $history));

        // It trusts what the token says: its expiration is what ends it.
        $this->assertNotNull($this->call($authentication, $this->bearer($this->token()))['user']);
        $this->assertCount(0, $history);
    }

    // -------------------------------------------------------------------------
    // The keys of the realm.
    // -------------------------------------------------------------------------

    #[Test]
    public function theKeysOfTheRealmAreAskedOnceWhenThereIsACache(): void
    {
        $cache = new ArrayAdapter();

        foreach ([1, 2, 3] as $request) {
            $this->assertNotNull($this->call($this->authentication(cache: $cache), $this->bearer($this->token()))['user']);
        }

        $this->assertSame(1, $this->http->requests);
    }

    #[Test]
    public function theKeysAreTheOnesOfTheRealmOfTheConfiguration(): void
    {
        $this->call($this->authentication(), $this->bearer($this->token()));

        $this->assertSame(self::ISSUER . '/protocol/openid-connect/certs', $this->http->lastUri);
    }
}

/**
 * What a realm answers when it is asked for its keys: always the same ones.
 */
final class FixedKeysClient implements ClientInterface
{
    public int $requests = 0;

    public string $lastUri = '';

    public function __construct(private readonly string $jwks)
    {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests++;
        $this->lastUri = (string) $request->getUri();

        return new Psr7Response(200, ['Content-Type' => 'application/json'], $this->jwks);
    }
}
