<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Keycloak;

use Derafu\Auth\Account\NewApiToken;
use Derafu\Auth\Authentication\Channel\Web\FormManager;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\FormException;
use Derafu\Auth\Provider\Keycloak\Account\Form\ApiTokenForm;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakAccountClient;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakApiTokenManager;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\User;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\Attributes\UsesNamespace;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Token creation uses the real form processor and CSRF middleware. Controlled
 * token endpoint responses exercise claims that a normal Keycloak never emits.
 */
#[CoversClass(KeycloakApiTokenManager::class)]
#[CoversClass(NewApiToken::class)]
#[UsesClass(FormManager::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(FormException::class)]
#[CoversClass(ApiTokenForm::class)]
#[UsesClass(KeycloakAccountClient::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(KeycloakUserRepository::class)]
#[UsesClass(KeycloakTokenVerifier::class)]
#[UsesClass(TokenClaims::class)]
#[UsesClass(KeycloakSessionManager::class)]
#[UsesClass(User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(\Derafu\Auth\Account\Form\ApiTokenValueForm::class)]
#[UsesNamespace('Derafu\\Auth')]
final class KeycloakApiTokenManagerTest extends TestCase
{
    /** @var list<RequestInterface> */
    private array $requests = [];

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $body
     */
    private function createToken(array $claims, array $body = ['password' => 'secret'], bool $authenticated = true): NewApiToken
    {
        $app = new SessionApp();
        $config = new KeycloakConfiguration([
            'keycloak_url' => 'https://keycloak.test',
            'realm' => 'test',
            'client_id' => 'app',
            'client_secret' => 'secret',
            'redirect_uri' => 'https://app.test/auth/callback',
        ]);
        $payload = json_encode($claims + ['typ' => 'Offline', 'sub' => 'user-1'], JSON_THROW_ON_ERROR);
        $token = 'eyJhbGciOiJIUzI1NiJ9.' . rtrim(strtr(base64_encode($payload), '+/', '-_'), '=') . '.signature';
        $stack = HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode(['refresh_token' => $token], JSON_THROW_ON_ERROR)),
        ]));
        $stack->push(Middleware::mapRequest(function (RequestInterface $request): RequestInterface {
            $this->requests[] = $request;
            return $request;
        }));
        $http = new Client(['handler' => $stack]);
        $manager = new KeycloakApiTokenManager(
            new KeycloakUserRepository($config, httpClient: $http),
            new KeycloakAccountClient($config, $http),
            new KeycloakSessionManager(),
            new FormManager(
                new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
                $app->processor(),
                Stack::formDefinitions()
            )
        );
        $request = $app->request('/auth/profile/tokens', body: [], csrf: false, captcha: false)
            ->withParsedBody($body + [FormInterface::CSRF_FIELD => $app->token(null, 'api_token')]);
        if ($authenticated) {
            $request = $request->withAttribute(MezzioUserInterface::class, new User('user-1', [], ['preferred_username' => 'otto']));
        }
        $result = null;
        $app->handle($request, function (ServerRequestInterface $request) use ($manager, &$result): void {
            $result = $manager->create($request, new Session([]));
        });
        $this->assertInstanceOf(NewApiToken::class, $result);

        return $result;
    }

    #[Test]
    public function aRequestWithoutAnAuthenticatedUserDoesNotCallKeycloak(): void
    {
        try {
            $this->createToken([], authenticated: false);
            $this->fail('Token creation requires an authenticated user.');
        } catch (AuthenticationException $e) {
            $this->assertSame(401, $e->getCode());
            $this->assertSame('There is no user in the session.', $e->getMessage());
            $this->assertSame([], $this->requests);
        }
    }

    #[Test]
    public function aTokenForAnotherUserCannotBeReturnedToTheSessionUser(): void
    {
        try {
            $this->createToken(['sub' => 'another-user']);
            $this->fail('A token belonging to another user must not be returned.');
        } catch (AuthenticationException $e) {
            $this->assertSame(400, $e->getCode());
            $this->assertSame('The token is not for the user of this session.', $e->getMessage());
            $this->assertCount(1, $this->requests);
        }
    }

    /** @param array<string, mixed> $claims */
    #[Test]
    #[DataProvider('validDates')]
    public function optionalDatesArePreservedWithoutCoercion(array $claims, ?int $createdAt, ?int $expiresAt): void
    {
        $result = $this->createToken($claims);

        $this->assertSame($createdAt, $result->createdAt);
        $this->assertSame($expiresAt, $result->expiresAt);
        $this->assertSame($claims + ['typ' => 'Offline', 'sub' => 'user-1'], TokenClaims::of($result->value));
    }

    /** @return iterable<string, array{array<string, mixed>, int|null, int|null}> */
    public static function validDates(): iterable
    {
        yield 'missing dates' => [[], null, null];
        yield 'null dates' => [['iat' => null, 'exp' => null], null, null];
        yield 'integer dates' => [['iat' => 1700000000, 'exp' => 1800000000], 1700000000, 1800000000];
        yield 'zero is not missing' => [['iat' => 0, 'exp' => 0], 0, 0];
    }

    #[Test]
    #[DataProvider('invalidDates')]
    public function malformedDatesReportTheClaimAndKeepTheReaderException(string $field, mixed $value): void
    {
        try {
            $this->createToken([$field => $value]);
            $this->fail('A malformed date must not create an API token.');
        } catch (AuthenticationException $e) {
            $this->assertSame(400, $e->getCode());
            $this->assertStringContainsString('The API token has invalid claims:', $e->getMessage());
            $this->assertInstanceOf(TranslatableInvalidArgumentException::class, $e->getPrevious());
            $this->assertStringContainsString($field, $e->getPrevious()->getMessage());
            $this->assertCount(1, $this->requests);
        }
    }

    /** @return iterable<string, array{string, mixed}> */
    public static function invalidDates(): iterable
    {
        foreach (['iat', 'exp'] as $field) {
            foreach (['numeric string' => '1700000000', 'boolean' => true, 'float' => 1700000000.5, 'array' => []] as $type => $value) {
                yield $field . ' as ' . $type => [$field, $value];
            }
        }
    }

    #[Test]
    public function passwordZeroAndTrimmedOtpReachTheTokenEndpoint(): void
    {
        $this->createToken([], ['password' => '0', 'totp' => ' 123456 ']);
        $this->assertCount(1, $this->requests);
        parse_str((string) $this->requests[0]->getBody(), $parameters);

        $this->assertSame('0', $parameters['password']);
        $this->assertSame('123456', $parameters['totp']);
        $this->assertSame('otto', $parameters['username']);
        $this->assertSame('openid offline_access', $parameters['scope']);
    }

    /** @param array<string, mixed> $body */
    #[Test]
    #[DataProvider('optionalOtp')]
    public function anOptionalOtpDoesNotSendAnEmptyParameter(array $body): void
    {
        $this->createToken([], ['password' => 'secret'] + $body);
        $this->assertCount(1, $this->requests);
        parse_str((string) $this->requests[0]->getBody(), $parameters);

        $this->assertArrayNotHasKey('totp', $parameters);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function optionalOtp(): iterable
    {
        yield 'absent' => [[]];
        yield 'empty' => [['totp' => '']];
        yield 'whitespace' => [['totp' => '   ']];
    }

    #[Test]
    public function anArrayOtpIsRejectedByTheFormBeforeCallingKeycloak(): void
    {
        try {
            $this->createToken([], ['password' => 'secret', 'totp' => ['123456']]);
            $this->fail('The form must reject an array OTP.');
        } catch (FormException $e) {
            $this->assertSame(400, $e->getCode());
            $this->assertSame([], $this->requests);
        }
    }

    private const NOT_VALID = 'The password is not valid.';

    private const CODE_MISSING = 'The password is not valid, or the code of the second factor is missing (your user has one).';

    private const PASSWORD_OR_CODE = 'The password or the code of the second factor is not valid.';

    private static function invalidGrant(string $description): Response
    {
        return new Response(400, [], (string) json_encode(['error' => 'invalid_grant', 'error_description' => $description]));
    }

    /**
     * What the account API says of the credentials of a user.
     */
    private static function credentials(bool $hasSecondFactor): Response
    {
        return new Response(200, [], (string) json_encode([
            ['type' => 'password', 'userCredentialMetadatas' => [['credential' => ['id' => '1']]]],
            ['type' => 'otp', 'userCredentialMetadatas' => $hasSecondFactor ? [['credential' => ['id' => '2']]] : []],
        ]));
    }

    /**
     * @return array<string, array{list<Response>, string, string, int}>
     */
    public static function provideAnswersOfKeycloak(): array
    {
        $invalid = static fn () => self::invalidGrant('Invalid user credentials');
        // The account API does not answer (the user is not told more than what is known).
        $withRoles = static fn () => new Response(403);

        return [
            'a user with a second factor, no code' => [[$invalid(), self::credentials(true)], '', self::CODE_MISSING, 401],
            'a user with a second factor, a code' => [[$invalid(), self::credentials(true)], '123456', self::PASSWORD_OR_CODE, 401],
            'a user without a second factor, no code' => [[$invalid(), self::credentials(false)], '', self::NOT_VALID, 401],
            'a user without a second factor, a code that it does not need' => [[$invalid(), self::credentials(false)], '123456', self::NOT_VALID, 401],
            'it is not known, no code' => [[$invalid(), $withRoles()], '', self::NOT_VALID, 401],
            'it is not known, a code' => [[$invalid(), $withRoles()], '123456', self::PASSWORD_OR_CODE, 401],
            'the user is disabled' => [[self::invalidGrant('Account disabled')], '', 'Your user is disabled.', 403],
            'the user has actions pending' => [
                [self::invalidGrant('Account is not fully set up')],
                '',
                'Your user has actions pending in Keycloak (a password to change, an email to verify...): complete them and try again.',
                403,
            ],
        ];
    }

    /**
     * @param list<Response> $answers What Keycloak answers, in order.
     */
    #[Test]
    #[DataProvider('provideAnswersOfKeycloak')]
    public function theUserIsToldWhatIsMoreLikelyToBeWrong(array $answers, string $code, string $message, int $status): void
    {
        $app = new SessionApp();
        $config = new KeycloakConfiguration([
            'keycloak_url' => 'https://keycloak.test',
            'realm' => 'test',
            'client_id' => 'my-site',
            'client_secret' => 'secret',
            'redirect_uri' => 'https://site.test/auth/callback',
        ]);
        // One queue of answers for the two clients: the token first, then the account.
        $http = new Client(['handler' => HandlerStack::create(new MockHandler($answers))]);
        $manager = new KeycloakApiTokenManager(
            new KeycloakUserRepository($config, httpClient: $http),
            new KeycloakAccountClient($config, $http),
            new KeycloakSessionManager(),
            new FormManager(new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))), $app->processor(), Stack::formDefinitions())
        );

        // The access token of the session: the account API asks for these roles.
        $encode = static fn (array $data): string => rtrim(strtr(base64_encode((string) json_encode($data)), '+/', '-_'), '=');
        $session = new Session(['oauth2_token' => $encode(['alg' => 'RS256']) . '.' . $encode(['resource_access' => ['account' => ['roles' => ['view-profile']]]]) . '.x']);

        $request = $app->request('/auth/profile/tokens', body: ['password' => 'x', 'totp' => $code], captcha: false, form: 'api_token')
            ->withAttribute(MezzioUserInterface::class, new User('ana', [], ['preferred_username' => 'ana']));

        try {
            $app->handle($request, fn (ServerRequestInterface $request) => $manager->create($request, $session));
            $this->fail('A token must not be made.');
        } catch (AuthenticationException $e) {
            $this->assertSame($message, $e->getMessage());
            $this->assertSame($status, $e->getCode());
        }
    }
}
