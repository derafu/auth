<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authentication\Channel\Api;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Channel\Api\ApiChannel;
use Derafu\Auth\Authentication\Channel\Api\ApiConfiguration;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Translation\TranslatorFactory;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * An unauthenticated request to the API gets a response with a title and a
 * detail, in the language of the translator, and in English without one.
 */
#[CoversClass(ApiChannel::class)]
#[UsesClass(ApiConfiguration::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class ApiChannelTest extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    private function unauthenticatedResponseOfTheApi(?string $locale): array
    {
        $channel = new ApiChannel(
            new ApiConfiguration(),
            $this->createStub(ApiSchemeInterface::class),
            translator: $locale === null
                ? null
                : TranslatorFactory::create($locale, [], [new AuthTranslationResourceProvider()])
        );

        $response = $channel->unauthorizedResponse(
            (new ServerRequest())->withUri(new Uri('https://example.com/api/items'))
        );

        $this->assertSame(401, $response->getStatusCode());

        return json_decode((string) $response->getBody(), true);
    }

    public function testTheResponseOfTheApiIsInEnglishWithoutATranslator(): void
    {
        $this->assertSame(
            [
                'status' => 401,
                'title' => 'Unauthorized',
                'detail' => 'You need to send valid credentials to access this resource.',
            ],
            $this->unauthenticatedResponseOfTheApi(null)
        );
    }

    public function testTheResponseOfTheApiIsTranslatedWithATranslator(): void
    {
        $this->assertSame(
            [
                'status' => 401,
                'title' => 'No autorizado',
                'detail' => 'Debes enviar credenciales válidas para acceder a este recurso.',
            ],
            $this->unauthenticatedResponseOfTheApi('es')
        );
    }
}
