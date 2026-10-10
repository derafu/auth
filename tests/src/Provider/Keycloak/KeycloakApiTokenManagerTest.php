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

use Derafu\Auth\Account\Form\ApiTokenValueForm;
use Derafu\Auth\Account\NewApiToken;
use Derafu\Auth\Authentication\Channel\Web\FormManager;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\FormException;
use Derafu\Auth\Provider\Keycloak\Account\Form\ApiTokenForm;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakAccountClient;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakApiTokenManager;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\User;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\SessionApp;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What the user is told when a token can not be made. Keycloak says the same for a
 * password that is not valid, for a code of the second factor that is not valid and
 * for one that is missing, so the message is worked out with what is known of the
 * user (if it has a second factor), and what Keycloak does tell (a user that is
 * disabled, or with actions pending) is said as it is.
 */
#[CoversClass(KeycloakApiTokenManager::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(KeycloakUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(KeycloakAccountClient::class)]
#[UsesClass(KeycloakSessionManager::class)]
#[UsesClass(FormManager::class)]
#[UsesClass(ApiTokenForm::class)]
#[UsesClass(ApiTokenValueForm::class)]
#[UsesClass(NewApiToken::class)]
#[UsesClass(TokenClaims::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(FormException::class)]
#[UsesClass(User::class)]
final class KeycloakApiTokenManagerTest extends TestCase
{
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
            new FormManager(new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))), $app->processor(), $config)
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
