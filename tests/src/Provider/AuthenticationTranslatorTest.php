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

use Derafu\Auth\Abstract\AbstractProviderAuthentication;
use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Provider\Database\DatabaseAuthentication;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\Provider\Keycloak\KeycloakAuthentication;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\User;
use Derafu\Translation\TranslatorFactory;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The providers give their translator to the authentication, so the response to
 * an unauthenticated request to the API is in the language of the application.
 */
#[CoversClass(DatabaseAuthentication::class)]
#[CoversClass(KeycloakAuthentication::class)]
#[UsesClass(AbstractProviderAuthentication::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(User::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class AuthenticationTranslatorTest extends TestCase
{
    /**
     * A configuration that has the path of the API that the tests ask for.
     *
     * @template T of \Derafu\Auth\Contract\ConfigurationInterface
     * @param class-string<T> $class
     * @return T&\PHPUnit\Framework\MockObject\Stub
     */
    private static function configuration(self $test, string $class): object
    {
        $config = $test->createStub($class);
        $config->method('getApiPaths')->willReturn(['/api']);

        return $config;
    }

    /**
     * @return array<string, array{callable(self, TranslatorInterface|null): AbstractProviderAuthentication}>
     */
    public static function provideProviders(): array
    {
        return [
            'database' => [
                fn (self $test, ?TranslatorInterface $translator) => new DatabaseAuthentication(
                    $test->createStub(DatabaseUserRepository::class),
                    self::configuration($test, DatabaseConfiguration::class),
                    $test->createStub(SessionManagerInterface::class),
                    $test->createStub(FormManagerInterface::class),
                    translator: $translator
                ),
            ],
            'keycloak' => [
                fn (self $test, ?TranslatorInterface $translator) => new KeycloakAuthentication(
                    $test->createStub(KeycloakUserRepository::class),
                    self::configuration($test, KeycloakConfiguration::class),
                    $test->createStub(KeycloakSessionManager::class),
                    translator: $translator
                ),
            ],
        ];
    }

    /**
     * @param callable(self, TranslatorInterface|null): AbstractProviderAuthentication $provider
     */
    #[DataProvider('provideProviders')]
    public function testTheResponseOfTheApiIsInTheLanguageOfTheTranslator(callable $provider): void
    {
        $request = (new ServerRequest())->withUri(new Uri('https://example.com/api/items'));

        $english = $provider($this, null)->unauthorizedResponse($request);
        $spanish = $provider($this, TranslatorFactory::create('es', [], [new AuthTranslationResourceProvider()]))
            ->unauthorizedResponse($request);

        $this->assertSame('Unauthorized', json_decode((string) $english->getBody(), true)['title']);
        $this->assertSame('No autorizado', json_decode((string) $spanish->getBody(), true)['title']);
    }
}
