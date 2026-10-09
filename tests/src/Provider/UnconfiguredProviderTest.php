<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\AuthenticationManager;
use Derafu\Auth\Authentication\Channel\Api\ApiChannel;
use Derafu\Auth\Authentication\Channel\Api\ApiConfiguration;
use Derafu\Auth\Authentication\Channel\Api\Scheme\BasicScheme;
use Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme;
use Derafu\Auth\Authentication\Channel\Web\FormManager;
use Derafu\Auth\Authentication\Channel\Web\SessionManager;
use Derafu\Auth\Authentication\Channel\Web\WebChannel;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Authentication\Identification;
use Derafu\Auth\Authorization\AccessRules;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Provider\Database\Api\DatabaseBasicScheme;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\Provider\Database\Web\DatabaseWebFlow;
use Derafu\Auth\Provider\Htpasswd\Api\HtpasswdBasicScheme;
use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;
use Derafu\Auth\Provider\Htpasswd\HtpasswdUserRepository;
use Derafu\Auth\Provider\Htpasswd\Web\HtpasswdWebFlow;
use Derafu\Auth\Provider\Keycloak\Api\KeycloakBearerScheme;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow;
use Derafu\Auth\User;
use Derafu\Auth\UserFactory;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * A provider that is not configured fails where it is used, and says which
 * variable to set. The rest of the site works: the pages that nobody protects
 * are answered without the provider, and so are the logout and a request to the
 * API that sends no credentials.
 *
 * This is what lets a site with a misconfigured provider show its error page in
 * HTML, because the error page is one of the pages that do not need it.
 */
#[CoversClass(AuthenticationManager::class)]
#[CoversClass(WebChannel::class)]
#[CoversClass(ApiChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\SameOrigin::class)]
#[UsesClass(Identification::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(User::class)]
#[UsesClass(UserFactory::class)]
#[UsesClass(AccessRules::class)]
#[UsesClass(WebConfiguration::class)]
#[UsesClass(ApiConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\Flash::class)]
#[UsesClass(SessionManager::class)]
#[UsesClass(KeycloakSessionManager::class)]
#[UsesClass(FormManager::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(KeycloakUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier::class)]
#[UsesClass(KeycloakWebFlow::class)]
#[UsesClass(KeycloakBearerScheme::class)]
#[UsesClass(DatabaseConfiguration::class)]
#[UsesClass(DatabaseUserRepository::class)]
#[UsesClass(DatabaseWebFlow::class)]
#[UsesClass(DatabaseBasicScheme::class)]
#[UsesClass(HtpasswdConfiguration::class)]
#[UsesClass(HtpasswdUserRepository::class)]
#[UsesClass(HtpasswdWebFlow::class)]
#[UsesClass(HtpasswdBasicScheme::class)]
#[UsesClass(BasicScheme::class)]
#[UsesClass(BearerScheme::class)]
#[UsesClass(ConfigurationException::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationMiddleware::class)]
final class UnconfiguredProviderTest extends TestCase
{
    private const SETTINGS = ['enabled' => true, 'protected_paths' => ['/private', '/api']];

    private SessionApp $app;

    protected function setUp(): void
    {
        $this->app = new SessionApp();
    }

    /**
     * Each provider with nothing configured: the authentication, the path of its
     * login, the variable that its error names, the credentials of the header
     * that the API reads, and what the session of a user that logged in before
     * has (the configuration was there then).
     *
     * @return array<string, array{callable(): AuthenticationInterface, string, string, string, array<string, mixed>}>
     */
    public static function provideProviders(): array
    {
        return [
            'keycloak' => [
                static function (): AuthenticationInterface {
                    $config = Stack::keycloakConfiguration(self::SETTINGS);

                    return Stack::keycloak(new KeycloakUserRepository($config), $config, new KeycloakSessionManager());
                },
                '/auth/callback',
                'AUTH_KEYCLOAK_URL',
                'Bearer a-token',
                ['oauth2_token' => ['access_token' => 'x'], 'user' => ['identity' => 'ana']],
            ],
            'database' => [
                static function (): AuthenticationInterface {
                    $config = Stack::databaseConfiguration(self::SETTINGS);

                    return Stack::database(
                        new DatabaseUserRepository($config),
                        $config,
                        new SessionManager(),
                        new FormManager(new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))), (new SessionApp())->processor(), $config)
                    );
                },
                '/auth/login',
                'AUTH_DATABASE_URL',
                'Basic ' . 'YW5hOnNlY3JldA==',
                ['user' => ['identity' => 'ana', 'roles' => ['admin'], 'details' => []]],
            ],
            'htpasswd' => [
                static function (): AuthenticationInterface {
                    $config = Stack::htpasswdConfiguration(self::SETTINGS);

                    return Stack::htpasswd(
                        new HtpasswdUserRepository($config),
                        $config,
                        new SessionManager(),
                        new FormManager(new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))), (new SessionApp())->processor(), $config)
                    );
                },
                '/auth/login',
                'AUTH_HTPASSWD_PATH',
                'Basic ' . 'YW5hOnNlY3JldA==',
                ['user' => ['identity' => 'ana']],
            ],
        ];
    }

    /**
     * @param callable(): AuthenticationInterface $authentication
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function aPageThatNobodyProtectsIsAnsweredWithoutTheProvider(callable $authentication, string $login, string $variable, string $credentials, array $session): void
    {
        $response = $this->app->handleAuthenticated($this->app->request('/'), $authentication(), fn () => null);

        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * @param callable(): AuthenticationInterface $authentication
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function aProtectedPageSaysWhichVariableIsMissing(callable $authentication, string $login, string $variable, string $credentials, array $session): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($variable);

        $this->app->handleAuthenticated($this->app->request('/private/page'), $authentication(), fn () => null);
    }

    /**
     * @param callable(): AuthenticationInterface $authentication
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function theLoginPageSaysWhichVariableIsMissingBeforeTheUserFillsAnything(callable $authentication, string $login, string $variable, string $credentials, array $session): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($variable);

        $this->app->handleAuthenticated($this->app->request($login), $authentication(), fn () => null);
    }

    /**
     * @param callable(): AuthenticationInterface $authentication
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function theLogoutNeedsNoConfiguration(callable $authentication, string $login, string $variable, string $credentials, array $session): void
    {
        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/logout', body: []),
            $authentication(),
            fn () => null
        );

        $this->assertSame(302, $response->getStatusCode());
    }

    /**
     * @param callable(): AuthenticationInterface $authentication
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function theCredentialsOfTheApiSayWhichVariableIsMissing(callable $authentication, string $login, string $variable, string $credentials, array $session): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($variable);

        $this->app->handleAuthenticated(
            $this->app->request('/api/items', headers: ['Authorization' => $credentials]),
            $authentication(),
            fn () => null
        );
    }

    /**
     * @param callable(): AuthenticationInterface $authentication
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function aRequestToTheApiWithoutCredentialsIsA401NotAnError(callable $authentication, string $login, string $variable, string $credentials, array $session): void
    {
        $response = $this->app->handleAuthenticated($this->app->request('/api/items'), $authentication(), fn () => null);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertNotSame('', $response->getHeaderLine('WWW-Authenticate'));
    }

    /**
     * @param callable(): AuthenticationInterface $authentication
     * @param array<string, mixed> $session
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function aSessionThatWasOpenedWhenTheProviderWasConfiguredDoesNotTakeDownThePagesThatNobodyProtects(callable $authentication, string $login, string $variable, string $credentials, array $session): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = $session;

        $user = null;
        $response = $this->app->handleAuthenticated(
            $this->app->request('/'),
            $authentication(),
            function ($request) use (&$user): null {
                $user = $request->getAttribute(\Mezzio\Authentication\UserInterface::class);

                return null;
            }
        );

        $this->assertSame(200, $response->getStatusCode());
        // What the session says can not be checked without the provider, so it is
        // not believed: the visitor is the anonymous one.
        $this->assertTrue($user?->isAnonymous());
    }

    /**
     * @param callable(): AuthenticationInterface $authentication
     * @param array<string, mixed> $session
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function aSessionThatWasOpenedBeforeStillSaysWhichVariableIsMissingWhereTheProviderIsNeeded(callable $authentication, string $login, string $variable, string $credentials, array $session): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = $session;

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($variable);

        $this->app->handleAuthenticated($this->app->request('/private/page'), $authentication(), fn () => null);
    }
}
