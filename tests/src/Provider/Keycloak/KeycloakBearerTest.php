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
use Derafu\Auth\Authentication\Channel\Web\WebChannel;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\Provider\Keycloak\Api\KeycloakBearerScheme;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow;
use Derafu\Auth\Web\AuthController;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Laminas\Diactoros\Response\JsonResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\Session;
use Mezzio\Session\SessionMiddleware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\Attributes\UsesNamespace;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;
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
#[CoversClass(WebChannel::class)]
#[CoversClass(AuthController::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\Flash::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authorization\AccessRules::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme::class)]
#[CoversClass(KeycloakBearerScheme::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authorization\AuthorizationManager::class)]
#[UsesClass(\Derafu\Auth\Exception\AuthenticationException::class)]
#[UsesClass(\Derafu\Auth\Exception\ConfigurationException::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\TokenClaims::class)]
#[UsesClass(KeycloakSessionManager::class)]
#[CoversClass(KeycloakUserRepository::class)]
#[UsesClass(ProviderUnavailableException::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\SessionManager::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationMiddleware::class)]
#[UsesNamespace('Derafu\\Auth')]
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
     * `unauthorizedResponse()` of the API throws instead of returning: the
     * status and the headers of the exception are what the package guarantees,
     * so the stand-in response here carries exactly those.
     *
     * @param array<string, string> $headers
     * @return array{response: ResponseInterface, user: UserInterface|null}
     */
    private function call(AuthenticationInterface $authentication, array $headers = [], string $path = '/api/items'): array
    {
        $user = null;
        try {
            $response = $this->app->handleAuthenticated(
                $this->app->request($path, headers: $headers),
                $authentication,
                function (ServerRequestInterface $request) use (&$user): null {
                    $user = $request->getAttribute(MezzioUserInterface::class);
                    $this->assertTrue($user === null || $user instanceof UserInterface);

                    return null;
                }
            );
        } catch (AuthenticationException $e) {
            $headers = $e->getHeaders();
            $validatedHeaders = [];
            foreach ($headers as $name => $value) {
                $this->assertTrue($name !== '');
                $validatedHeaders[$name] = $value;
            }
            $headers = $validatedHeaders;
            $response = new JsonResponse(['status' => $e->getCode()], $e->getCode(), $headers);
        }

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
     * The token that is not valid, and the reason that the client is told.
     *
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function provideClaimsThatAreNotValid(): array
    {
        $issuer = 'The issuer of the token is not the realm.';
        $type = 'The token is not an access token.';
        $audience = 'The audience of the token is not this API.';

        return [
            'expired, past the margin of the clocks' => [['exp' => time() - 300], 'The token has expired.'],
            // Far away: the provider is evaluated when the suite starts, and the test
            // runs minutes later, so a near `nbf` would end up inside the margin.
            'not valid yet' => [['nbf' => time() + 100 * 365 * 86400], 'The token is not valid yet.'],
            'from another realm' => [['iss' => 'https://keycloak.test/realms/other'], $issuer],
            'from another server' => [['iss' => 'https://evil.test/realms/test'], $issuer],
            'without an issuer' => [['iss' => null], $issuer],
            'an ID token' => [['typ' => 'ID'], $type],
            'a refresh token' => [['typ' => 'Refresh'], $type],
            'an offline token' => [['typ' => 'Offline'], 'Keycloak did not accept the offline token.'],
            'a token without type' => [['typ' => null], $type],
            'a type that is not the one of Keycloak' => [['typ' => 'bearer'], $type],
            'without an audience' => [['aud' => null], $audience],
            'with the audience of another API' => [['aud' => ['another-api']], $audience],
            'with the audience of another API, as text' => [['aud' => 'another-api'], $audience],
            'with only the default audience of Keycloak' => [['aud' => ['account']], $audience],
            'with an empty audience' => [['aud' => []], $audience],
            'with an audience that only looks alike' => [['aud' => ['derafu-api-extra', 'derafu']], $audience],
            'without a user' => [['sub' => null], 'The token is not valid.'],
        ];
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[Test]
    #[DataProvider('provideClaimsThatAreNotValid')]
    public function aTokenThatIsNotValidIsNotAuthenticatedAndTheClientIsToldWhy(array $claims, string $reason): void
    {
        $result = $this->call($this->authentication(), $this->bearer($this->token($claims)));

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
        $this->assertSame(
            sprintf('Bearer realm="API", error="invalid_token", error_description="%s"', $reason),
            $result['response']->getHeaderLine('WWW-Authenticate')
        );
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
     * @param ArrayObject<int, array{request: RequestInterface}>|null $history
     * Where what was asked is kept.
     */
    private function keycloak(array $answers, ?ArrayObject $history = null): GuzzleClient
    {
        $stack = HandlerStack::create(new MockHandler($answers));
        if ($history !== null) {
            $stack->push(Middleware::mapRequest(static function (RequestInterface $request) use ($history): RequestInterface {
                $history[] = ['request' => $request];
                return $request;
            }));
        }

        return new GuzzleClient(['handler' => $stack]);
    }

    /**
     * @return ArrayObject<int, array{request: RequestInterface}>
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
        $entry = $history[0];
        $this->assertIsArray($entry);
        $this->assertArrayHasKey('request', $entry);
        $request = $entry['request'];
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

        $entry = $history[0];
        $this->assertIsArray($entry);
        $this->assertArrayHasKey('request', $entry);
        $request = $entry['request'];
        $this->assertInstanceOf(RequestInterface::class, $request);
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame(self::ISSUER . '/protocol/openid-connect/token/introspect', (string) $request->getUri());
        parse_str((string) $request->getBody(), $form);
        $this->assertSame('access_token', $form['token_type_hint']);
        $this->assertIsString($form['token']);
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
        $this->assertSame(
            'Bearer realm="API", error="invalid_token", error_description="The token is not active."',
            $result['response']->getHeaderLine('WWW-Authenticate')
        );
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

    /** @return iterable<string, array{string, string}> */
    public static function invalidTokenResponses(): iterable
    {
        yield 'ID token during login' => ['login', 'id_token'];
        yield 'access token during login' => ['login', 'access_token'];
        yield 'access token during session refresh' => ['refresh', 'access_token'];
        yield 'access token during offline exchange' => ['offline', 'access_token'];
    }

    #[DataProvider('invalidTokenResponses')]
    public function testRejectsNonStringTokensFromTheTokenEndpoint(string $stage, string $key): void
    {
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::URL,
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'a-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'api_audience' => 'derafu-api',
            'api_introspection' => false,
        ]);
        $answer = [
            'access_token' => $this->token(),
            'refresh_token' => 'renewed-refresh-token',
            'id_token' => $this->token(['aud' => 'derafu-auth', 'nonce' => 'login-nonce']),
            'expires_in' => 300,
        ];
        $answer[$key] = ['unexpected'];
        $repository = new KeycloakUserRepository(
            $config,
            new KeycloakTokenVerifier($config, null, $this->http, new HttpFactory()),
            httpClient: $this->keycloak([new Psr7Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode($answer, JSON_THROW_ON_ERROR)
            )])
        );
        $session = new Session([
            'oauth2_state' => 'login-state',
            'oauth2_nonce' => 'login-nonce',
            'oauth2_pkce' => 'pkce-verifier',
            'oauth2_refresh_token' => 'original-refresh-token',
            'oauth2_expiry' => time() - 1,
            'user' => ['sub' => 'existing-user'],
        ]);
        $flow = new KeycloakWebFlow($repository, $config, new WebConfiguration([]), new KeycloakSessionManager());

        if ($stage === 'login') {
            try {
                $flow->login($this->app->request('/auth/callback', ['state' => 'login-state', 'code' => 'code']), $session);
                $this->fail('The invalid token must be rejected before the user is logged in.');
            } catch (AuthenticationException $e) {
                $this->assertSame(400, $e->getCode());
                $this->assertInstanceOf(TranslatableInvalidArgumentException::class, $e->getPrevious());
                $this->assertStringContainsString('"' . $key . '"', $e->getPrevious()->getMessage());
                $this->assertSame('original-refresh-token', $session->get('oauth2_refresh_token'));
                $this->assertSame(['sub' => 'existing-user'], $session->get('user'));
            }

            return;
        }

        try {
            if ($stage === 'refresh') {
                $flow->userFromSession($session);
            } else {
                (new KeycloakBearerScheme($repository, $config))->authenticate(
                    $this->app->request('/api/items'),
                    $this->token(['typ' => 'Offline'])
                );
            }
            $this->fail('The invalid access token must be rejected.');
        } catch (TranslatableInvalidArgumentException $e) {
            $this->assertStringContainsString('"access_token"', $e->getMessage());
            if ($stage === 'refresh') {
                $this->assertSame('renewed-refresh-token', $session->get('oauth2_refresh_token'));
                $this->assertSame(['sub' => 'existing-user'], $session->get('user'));
            }
        }
    }

    /** @param list<Psr7Response> $answers */
    private function flowWithResponses(array $answers): KeycloakWebFlow
    {
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::URL,
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'a-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
        ]);
        $repository = new KeycloakUserRepository(
            $config,
            new KeycloakTokenVerifier($config, null, $this->http, new HttpFactory()),
            httpClient: $this->keycloak($answers)
        );

        return new KeycloakWebFlow($repository, $config, new WebConfiguration([]), new KeycloakSessionManager());
    }

    public function testMissingIdTokenKeepsTheExistingAuthenticationError(): void
    {
        $flow = $this->flowWithResponses([new Psr7Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => $this->token(),
            'expires_in' => 300,
        ], JSON_THROW_ON_ERROR))]);
        $session = new Session(['oauth2_state' => 'state', 'oauth2_pkce' => 'verifier']);
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The ID token was not received.');

        $flow->login($this->app->request('/auth/callback', ['state' => 'state', 'code' => 'code']), $session);
    }

    public function testExpiredSessionWithoutARefreshTokenIsCleared(): void
    {
        $session = new Session([
            'oauth2_token' => 'expired',
            'oauth2_expiry' => time() - 1,
            'user' => ['sub' => 'user-1'],
            'auth_redirect' => '/private',
        ]);
        $user = $this->flowWithResponses([])->userFromSession($session);

        $this->assertNotNull($user);
        $this->assertTrue($user->isAnonymous());
        $this->assertSame([], $session->toArray());
    }

    public function testAnEmptySessionHasNoUser(): void
    {
        $this->assertNull($this->flowWithResponses([])->userFromSession(new Session([])));
    }

    public function testUnavailableUserInfoKeepsTheRenewedTokensAndForcesAnotherCheck(): void
    {
        $accessToken = $this->token(['azp' => 'derafu-auth']);
        $flow = $this->flowWithResponses([
            new Psr7Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => $accessToken,
                'refresh_token' => 'renewed-refresh-token',
                'expires_in' => 300,
            ], JSON_THROW_ON_ERROR)),
            new Psr7Response(503, ['Content-Type' => 'application/json'], '{"error":"temporarily_unavailable"}'),
        ]);
        $session = new Session([
            'oauth2_token' => 'old-access-token',
            'oauth2_refresh_token' => 'old-refresh-token',
            'oauth2_expiry' => time() - 1,
            'auth_checked_at' => time() - 600,
            'user' => ['sub' => 'user-1'],
        ]);

        $this->assertNull($flow->userFromSession($session));
        $this->assertSame($accessToken, $session->get('oauth2_token'));
        $this->assertSame('renewed-refresh-token', $session->get('oauth2_refresh_token'));
        $this->assertSame(['sub' => 'user-1'], $session->get('user'));
        $this->assertNull($session->get('auth_checked_at'));
    }

    /**
     * @param list<Psr7Response> $answers
     * @return array{KeycloakBearerScheme, MockHandler}
     */
    private function offlineScheme(array $answers, ?ArrayAdapter $cache): array
    {
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::URL,
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'a-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'api_audience' => 'derafu-api',
            'api_introspection' => false,
        ]);
        $queue = new MockHandler($answers);
        $repository = new KeycloakUserRepository(
            $config,
            new KeycloakTokenVerifier($config, null, $this->http, new HttpFactory()),
            httpClient: new GuzzleClient(['handler' => HandlerStack::create($queue)])
        );

        return [new KeycloakBearerScheme($repository, $config, $cache), $queue];
    }

    /** @param array<string, mixed> $expiration */
    private function offlineAnswer(string $accessToken, array $expiration = []): Psr7Response
    {
        return new Psr7Response(200, ['Content-Type' => 'application/json'], json_encode(
            ['access_token' => $accessToken, 'refresh_token' => 'renewed-refresh-token'] + $expiration,
            JSON_THROW_ON_ERROR
        ));
    }

    #[DataProvider('invalidCachedAccessTokens')]
    public function testInvalidCachedAccessTokensAreReplacedAndTheReplacementIsReused(mixed $cached): void
    {
        $offline = $this->token(['typ' => 'Offline']);
        $key = 'derafu_auth.offline.' . hash('sha256', $offline);
        $cache = new ArrayAdapter();
        $cache->save($cache->getItem($key)->set($cached));
        $accessToken = $this->token();
        [$scheme, $queue] = $this->offlineScheme([
            $this->offlineAnswer($accessToken, ['expires_in' => 300]),
        ], $cache);

        foreach ([1, 2] as $request) {
            $user = $scheme->authenticate($this->app->request('/api/items'), $offline);
            $this->assertNotNull($user);
            $this->assertSame('user-1', $user->getIdentity());
        }

        $this->assertCount(0, $queue);
        $this->assertTrue($cache->getItem($key)->isHit());
        $this->assertSame($accessToken, $cache->getItem($key)->get());
    }

    /** @return iterable<string, array{mixed}> */
    public static function invalidCachedAccessTokens(): iterable
    {
        yield 'null' => [null];
        yield 'false' => [false];
        yield 'true' => [true];
        yield 'integer' => [42];
        yield 'float' => [1.5];
        yield 'array' => [['unexpected']];
        yield 'object' => [new stdClass()];
        yield 'empty string' => [''];
        yield 'malformed JWT' => ['not-a-jwt'];
    }

    public function testAValidCachedAccessTokenDoesNotCallTheTokenEndpoint(): void
    {
        $offline = $this->token(['typ' => 'Offline']);
        $key = 'derafu_auth.offline.' . hash('sha256', $offline);
        $cache = new ArrayAdapter();
        $accessToken = $this->token();
        $cache->save($cache->getItem($key)->set($accessToken));
        [$scheme, $queue] = $this->offlineScheme([], $cache);

        $user = $scheme->authenticate($this->app->request('/api/items'), $offline);

        $this->assertNotNull($user);
        $this->assertSame('user-1', $user->getIdentity());
        $this->assertSame($accessToken, $cache->getItem($key)->get());
        $this->assertCount(0, $queue);
    }

    public function testAnExpiredCachedAccessTokenIsExchangedAgain(): void
    {
        $offline = $this->token(['typ' => 'Offline']);
        $key = 'derafu_auth.offline.' . hash('sha256', $offline);
        $cache = new ArrayAdapter();
        $cache->save($cache->getItem($key)->set($this->token(['iat' => time() - 600, 'exp' => time() - 300])));
        $accessToken = $this->token();
        [$scheme, $queue] = $this->offlineScheme([
            $this->offlineAnswer($accessToken, ['expires_in' => 300]),
        ], $cache);

        $this->assertNotNull($scheme->authenticate($this->app->request('/api/items'), $offline));
        $this->assertCount(0, $queue);
        $this->assertSame($accessToken, $cache->getItem($key)->get());
    }

    public function testAnInvalidCacheEntryIsRemovedEvenWhenKeycloakRefusesTheExchange(): void
    {
        $offline = $this->token(['typ' => 'Offline']);
        $key = 'derafu_auth.offline.' . hash('sha256', $offline);
        $cache = new ArrayAdapter();
        $cache->save($cache->getItem($key)->set(['unexpected']));
        [$scheme, $queue] = $this->offlineScheme([
            new Psr7Response(400, [], '{"error":"invalid_grant"}'),
        ], $cache);

        try {
            $scheme->authenticate($this->app->request('/api/items'), $offline);
            $this->fail('A refused exchange must not authenticate the user.');
        } catch (AuthenticationException $e) {
            $this->assertSame(401, $e->getCode());
            $this->assertSame('Keycloak did not accept the offline token.', $e->getMessage());
            $this->assertFalse($cache->getItem($key)->isHit());
            $this->assertCount(0, $queue);
        }
    }

    public function testTheCachedTokenExpiresWithTheExistingThirtySecondMargin(): void
    {
        $offline = $this->token(['typ' => 'Offline']);
        $key = 'derafu_auth.offline.' . hash('sha256', $offline);
        $cache = new ArrayAdapter();
        $expires = time() + 300;
        [$scheme] = $this->offlineScheme([
            $this->offlineAnswer($this->token(), ['expires' => $expires]),
        ], $cache);

        $this->assertNotNull($scheme->authenticate($this->app->request('/api/items'), $offline));
        $item = $cache->getItem($key);
        $this->assertTrue($item->isHit());
        $this->assertSame((float) ($expires - 30), $item->getMetadata()['expiry']);
    }

    /** @param array<string, mixed> $expiration */
    #[DataProvider('optionalOfflineExpiration')]
    public function testAnAccessTokenWithoutExpirationAuthenticatesButIsNotCached(array $expiration): void
    {
        $offline = $this->token(['typ' => 'Offline']);
        $key = 'derafu_auth.offline.' . hash('sha256', $offline);
        $cache = new ArrayAdapter();
        $answer = $this->offlineAnswer($this->token(), $expiration);
        [$scheme, $queue] = $this->offlineScheme([$answer, $answer], $cache);

        foreach ([1, 2] as $request) {
            $this->assertNotNull($scheme->authenticate($this->app->request('/api/items'), $offline));
            $this->assertFalse($cache->getItem($key)->isHit());
        }
        $this->assertCount(0, $queue);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function optionalOfflineExpiration(): iterable
    {
        yield 'missing expiration' => [[]];
        yield 'explicit null' => [['expires' => null]];
    }

    #[DataProvider('fractionalOfflineExpirations')]
    public function testFractionalExpirationsAreRejectedWithOrWithoutACache(float|string $duration, bool $withCache): void
    {
        $offline = $this->token(['typ' => 'Offline']);
        $cache = $withCache ? new ArrayAdapter() : null;
        // OAuth2 Client adds expires_in to the current time; a fractional
        // duration therefore produces a float timestamp in refreshToken().
        [$scheme, $queue] = $this->offlineScheme([
            $this->offlineAnswer($this->token(), ['expires_in' => $duration]),
        ], $cache);

        try {
            $scheme->authenticate($this->app->request('/api/items'), $offline);
            $this->fail('An expiration timestamp must be an integer.');
        } catch (TranslatableInvalidArgumentException $e) {
            $this->assertStringContainsString('"expires"', $e->getMessage());
            $this->assertCount(0, $queue);
            if ($cache !== null) {
                $key = 'derafu_auth.offline.' . hash('sha256', $offline);
                $this->assertFalse($cache->getItem($key)->isHit());
            }
        }
    }

    /** @return iterable<string, array{float|string, bool}> */
    public static function fractionalOfflineExpirations(): iterable
    {
        yield 'float with cache' => [300.5, true];
        yield 'float without cache' => [300.5, false];
        yield 'numeric string with cache' => ['300.5', true];
        yield 'numeric string without cache' => ['300.5', false];
    }

    #[DataProvider('invalidIdTokenNonces')]
    public function testIdTokenNoncesMustBeStringsMatchingTheLogin(mixed $nonce): void
    {
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::URL, 'realm' => 'test', 'client_id' => 'derafu-auth',
        ]);
        $verifier = new KeycloakTokenVerifier($config, null, $this->http, new HttpFactory());
        $token = $this->token(['aud' => 'derafu-auth', 'nonce' => $nonce]);
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The nonce of the token is not the one of the login.');

        $verifier->verifyIdToken($token, '123');
    }

    /** @return iterable<string, array{mixed}> */
    public static function invalidIdTokenNonces(): iterable
    {
        yield 'missing nonce' => [null];
        yield 'integer is not a string nonce' => [123];
        yield 'boolean' => [true];
        yield 'float' => [123.0];
        yield 'array' => [['123']];
        yield 'different string' => ['another-nonce'];
    }

    public function testAStringNonceAndNestedClaimsArePreserved(): void
    {
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::URL, 'realm' => 'test', 'client_id' => 'derafu-auth',
        ]);
        $verifier = new KeycloakTokenVerifier($config, null, $this->http, new HttpFactory());
        $claims = $verifier->verifyIdToken($this->token([
            'aud' => 'derafu-auth', 'nonce' => '123',
            'custom' => ['nested' => ['label' => 'value'], 'items' => [1, 2]],
        ]), '123');

        $this->assertSame('123', $claims['nonce']);
        $this->assertSame(['nested' => ['label' => 'value'], 'items' => [1, 2]], $claims['custom']);
    }

    #[DataProvider('malformedKeySets')]
    public function testMalformedKeySetStructuresKeepTheirValidationCause(mixed $body, string $path): void
    {
        $http = new FixedKeysClient(json_encode($body, JSON_THROW_ON_ERROR));
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::URL, 'realm' => 'test', 'client_id' => 'derafu-auth',
        ]);
        $verifier = new KeycloakTokenVerifier($config, null, $http, new HttpFactory());

        try {
            $verifier->verifyBearerToken($this->token(), 'derafu-api');
            $this->fail('Malformed signing key data must not validate a token.');
        } catch (AuthenticationException $e) {
            $this->assertStringContainsString('Failed to validate the token:', $e->getMessage());
            $this->assertInstanceOf(TranslatableInvalidArgumentException::class, $e->getPrevious());
            $this->assertStringContainsString($path, $e->getPrevious()->getMessage());
        }
    }

    /** @return iterable<string, array{mixed, string}> */
    public static function malformedKeySets(): iterable
    {
        yield 'null root' => [null, 'jwks'];
        yield 'string root' => ['keys', 'jwks'];
        yield 'boolean root' => [true, 'jwks'];
        yield 'number root' => [42, 'jwks'];
        yield 'string keys' => [['keys' => 'invalid'], 'jwks.keys'];
        yield 'boolean keys' => [['keys' => false], 'jwks.keys'];
        yield 'null key record' => [['keys' => [null]], 'jwks.keys'];
        yield 'string key record' => [['keys' => ['invalid']], 'jwks.keys'];
        yield 'boolean key record' => [['keys' => [false]], 'jwks.keys'];
    }

    public function testSigningKeysWithoutUseAreAcceptedAndEncryptionKeysAreExcluded(): void
    {
        $jwks = json_decode(self::$jwks, true, flags: JSON_THROW_ON_ERROR);
        $this->assertIsArray($jwks);
        $keys = $jwks['keys'];
        $this->assertIsArray($keys);
        $signing = $keys[0];
        $this->assertIsArray($signing);
        unset($signing['use']);
        // An encryption key must not replace the signing key with the same kid.
        $encryption = ['use' => 'enc', 'n' => 'not-a-valid-modulus'] + $signing;
        $http = new FixedKeysClient(json_encode(['keys' => [$signing, $encryption]], JSON_THROW_ON_ERROR));
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::URL, 'realm' => 'test', 'client_id' => 'derafu-auth',
        ]);
        $verifier = new KeycloakTokenVerifier($config, null, $http, new HttpFactory());

        $claims = $verifier->verifyBearerToken($this->token(), 'derafu-api');

        $this->assertSame('user-1', $claims['sub']);
    }

    /** @param list<Psr7Response|\Throwable> $answers */
    private function tokenRepository(array $answers): KeycloakUserRepository
    {
        $config = new KeycloakConfiguration([
            'keycloak_url' => self::URL, 'realm' => 'test', 'client_id' => 'derafu-auth',
            'client_secret' => 'secret', 'redirect_uri' => 'https://app.test/auth/callback',
            'api_audience' => 'derafu-api',
        ]);

        return new KeycloakUserRepository(
            $config,
            new KeycloakTokenVerifier($config, null, $this->http, new HttpFactory()),
            httpClient: $this->keycloak($answers)
        );
    }

    #[Test]
    public function matchingUserInfoProducesTheAuthenticatedUserAndPreservesTokenClaims(): void
    {
        $answer = new Psr7Response(200, [], '{"sub":"user-1","email":"otto@example.com","preferred_username":"from-userinfo"}');
        $repository = $this->tokenRepository([$answer, $answer]);
        $token = $this->token(['azp' => 'derafu-auth']);

        $user = $repository->authenticate($token);

        $this->assertInstanceOf(UserInterface::class, $user);
        $this->assertSame('user-1', $user->getIdentity());
        $this->assertSame('otto@example.com', $user->getEmail());
        $this->assertSame('service-account-a-service', $user->getUsername());
        $this->assertTrue($user->hasRole('editor'));
        $this->assertTrue($repository->isTokenValid($token));
    }

    #[Test]
    public function userInfoForAnotherSubjectCannotAuthenticateTheTokenUser(): void
    {
        $repository = $this->tokenRepository([
            new Psr7Response(200, [], '{"sub":"another-user"}'),
        ]);
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The user of the user info is not the user of the token.');

        $repository->getUserInfoFromToken($this->token(['azp' => 'derafu-auth']));
    }

    #[Test]
    #[DataProvider('unavailableUserInfoResponses')]
    public function userInfoFailuresAreProviderErrorsRatherThanWrongCredentials(Psr7Response|\Throwable $answer): void
    {
        $repository = $this->tokenRepository([$answer]);
        $this->expectException(ProviderUnavailableException::class);
        $this->expectExceptionMessage('Failed to get user info:');

        $repository->getUserInfoFromToken($this->token(['azp' => 'derafu-auth']));
    }

    /** @return iterable<string, array{Psr7Response|\Throwable}> */
    public static function unavailableUserInfoResponses(): iterable
    {
        yield 'connection failure' => [new ConnectException('Connection failed', new Request('GET', self::ISSUER . '/protocol/openid-connect/userinfo'))];
        yield 'server error' => [new Psr7Response(503, [], '{"error":"temporarily_unavailable"}')];
        yield 'malformed JSON' => [new Psr7Response(200, ['Content-Type' => 'application/json'], '{')];
        yield 'scalar JSON' => [new Psr7Response(200, ['Content-Type' => 'application/json'], '123')];
    }

    #[Test]
    public function aRejectedUserInfoTokenDoesNotAuthenticate(): void
    {
        $answer = new Psr7Response(401, [], '{"error":"invalid_token"}');
        $repository = $this->tokenRepository([$answer, $answer]);
        $token = $this->token(['azp' => 'derafu-auth']);

        $this->assertNull($repository->authenticate($token));
        $this->assertFalse($repository->isTokenValid($token));
    }

    #[Test]
    public function anIntrospectionConnectionFailureKeepsItsCause(): void
    {
        $failure = new ConnectException('Connection failed', new Request('POST', self::ISSUER . '/protocol/openid-connect/token/introspect'));
        $repository = $this->tokenRepository([$failure]);

        try {
            $repository->verifyBearerToken($this->token());
            $this->fail('An unavailable introspection must not accept the token.');
        } catch (ProviderUnavailableException $e) {
            $this->assertSame($failure, $e->getPrevious());
        }
    }

    #[Test]
    #[DataProvider('unavailableOfflineResponses')]
    public function offlineTokenEndpointFailuresAreProviderErrors(Psr7Response|\Throwable $answer): void
    {
        $repository = $this->tokenRepository([$answer]);
        $this->expectException(ProviderUnavailableException::class);
        $this->expectExceptionMessage('Failed to ask Keycloak for a token:');

        $repository->requestOfflineToken('otto', 'secret');
    }

    /** @return iterable<string, array{Psr7Response|\Throwable}> */
    public static function unavailableOfflineResponses(): iterable
    {
        yield 'connection failure' => [new ConnectException('Connection failed', new Request('POST', self::ISSUER . '/protocol/openid-connect/token'))];
        yield 'server error' => [new Psr7Response(503, [], '{"error":"temporarily_unavailable"}')];
        yield 'non JSON response' => [new Psr7Response(200, [], 'not-json')];
        yield 'scalar JSON response' => [new Psr7Response(200, [], '123')];
    }

    #[Test]
    #[DataProvider('offlineClientRejections')]
    public function aClientThatCannotIssueOfflineTokensIsNotReportedAsABadPassword(string $error): void
    {
        $repository = $this->tokenRepository([new Psr7Response(400, [], json_encode(['error' => $error], JSON_THROW_ON_ERROR))]);
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(400);
        $this->expectExceptionMessage('direct access grants');

        $repository->requestOfflineToken('otto', 'secret');
    }

    /** @return iterable<string, array{string}> */
    public static function offlineClientRejections(): iterable
    {
        yield 'unauthorized client' => ['unauthorized_client'];
        yield 'invalid client' => ['invalid_client'];
    }

    #[Test]
    #[DataProvider('invalidOfflineTokens')]
    public function theOfflineEndpointMustActuallyReturnAnOfflineToken(mixed $refresh): void
    {
        $repository = $this->tokenRepository([new Psr7Response(200, [], json_encode(['refresh_token' => $refresh], JSON_THROW_ON_ERROR))]);
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(400);
        $this->expectExceptionMessage('The token that Keycloak gave is not one for the API.');

        $repository->requestOfflineToken('otto', 'secret');
    }

    /** @return iterable<string, array{mixed}> */
    public static function invalidOfflineTokens(): iterable
    {
        yield 'missing token' => [null];
        yield 'array token' => [['unexpected']];
        yield 'ordinary refresh token' => ['not-an-offline-jwt'];
    }

    #[Test]
    public function aProtectedWebPageRemembersItsQueryBeforeRedirectingToKeycloak(): void
    {
        $session = new Session([]);
        $request = $this->app->request('/private/page', ['tab' => '2'])
            ->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, $session);
        $channel = new WebChannel($this->flowWithResponses([]), new WebConfiguration(), new KeycloakSessionManager());

        $response = $channel->unauthorizedResponse($request);

        $this->assertStringStartsWith(self::ISSUER . '/protocol/openid-connect/auth?', $response->getHeaderLine('Location'));
        $this->assertSame('/private/page?tab=2', $session->get('auth_redirect'));
        $this->assertNotNull($session->get('oauth2_state'));
        $this->assertNotNull($session->get('oauth2_pkce'));
    }

    #[Test]
    public function aWebRequestWithoutSessionRemainsAnonymousAndRedirectsToTheLoginPage(): void
    {
        $request = $this->app->request('/private/page');
        $channel = new WebChannel($this->flowWithResponses([]), new WebConfiguration(['unauthorized_redirect_path' => '/auth/login']), new KeycloakSessionManager());

        $identification = $channel->identify($request);
        $this->assertTrue($identification->user()?->isAnonymous());
        $response = $channel->unauthorizedResponse($request);
        $this->assertSame('/auth/login', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function theKeycloakLoginPageWithoutSessionUsesTheConfiguredFallback(): void
    {
        $config = Stack::keycloakConfiguration([
            'keycloak_url' => self::URL, 'realm' => 'test', 'client_id' => 'derafu-auth',
            'client_secret' => 'secret', 'redirect_uri' => 'https://app.test/auth/callback',
            'login_redirect_path' => '/home',
        ]);
        $controller = Stack::keycloakController(new KeycloakUserRepository($config), $config, new KeycloakSessionManager());

        $response = $controller->login($this->app->request('/auth/login'));

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertSame('/home', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function aSuccessfulOfflineTokenResponsePreservesTheTokenAndItsOtherFields(): void
    {
        $offline = $this->token(['typ' => 'Offline']);
        $repository = $this->tokenRepository([new Psr7Response(200, [], json_encode([
            'refresh_token' => $offline, 'scope' => 'openid offline_access', 'expires_in' => 300,
        ], JSON_THROW_ON_ERROR))]);

        $answer = $repository->requestOfflineToken('otto', 'secret');

        $this->assertSame([
            'refresh_token' => $offline, 'scope' => 'openid offline_access', 'expires_in' => 300,
        ], $answer);
    }

    #[Test]
    #[DataProvider('offlineAccountRejections')]
    public function disabledOrIncompleteAccountsKeepTheirSpecificError(string $description, string $message): void
    {
        $repository = $this->tokenRepository([new Psr7Response(400, [], json_encode([
            'error' => 'invalid_grant', 'error_description' => $description,
        ], JSON_THROW_ON_ERROR))]);
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(403);
        $this->expectExceptionMessage($message);

        $repository->requestOfflineToken('otto', 'secret');
    }

    /** @return iterable<string, array{string, string}> */
    public static function offlineAccountRejections(): iterable
    {
        yield 'disabled account' => ['Account disabled', 'Your user is disabled.'];
        yield 'incomplete account' => ['Account is not fully set up', 'Your user has actions pending in Keycloak'];
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
