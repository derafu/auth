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
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\Provider\Database\Web\DatabaseWebFlow;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\User;
use Derafu\TestsAuth\Fixture\Stack;
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
#[CoversClass(DatabaseWebFlow::class)]
#[CoversClass(KeycloakWebFlow::class)]
#[UsesClass(AuthenticationManager::class)]
#[UsesClass(\Derafu\Auth\Authentication\Identification::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authorization\AccessRules::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\Scheme\BasicScheme::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\Api\DatabaseBasicScheme::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\Api\KeycloakBearerScheme::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(User::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class AuthenticationTranslatorTest extends TestCase
{
    /**
     * @return array<string, array{callable(self, TranslatorInterface|null): AuthenticationManager}>
     */
    public static function provideProviders(): array
    {
        return [
            'database' => [
                fn (self $test, ?TranslatorInterface $translator) => Stack::database(
                    $test->createStub(DatabaseUserRepository::class),
                    $test->createStub(DatabaseConfiguration::class),
                    $test->createStub(SessionManagerInterface::class),
                    $test->createStub(FormManagerInterface::class),
                    translator: $translator
                ),
            ],
            'keycloak' => [
                fn (self $test, ?TranslatorInterface $translator) => Stack::keycloak(
                    $test->createStub(KeycloakUserRepository::class),
                    $test->createStub(KeycloakConfiguration::class),
                    $test->createStub(KeycloakSessionManager::class),
                    translator: $translator
                ),
            ],
        ];
    }

    /**
     * @param callable(self, TranslatorInterface|null): AuthenticationManager $provider
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
