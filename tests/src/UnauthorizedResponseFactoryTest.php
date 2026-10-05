<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth;

use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\UnauthorizedResponseFactory;
use Derafu\Translation\TranslatorFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The response for a user that is not authorized is in the language of the
 * translator, and in English without one.
 */
#[CoversClass(UnauthorizedResponseFactory::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class UnauthorizedResponseFactoryTest extends TestCase
{
    public function testTheResponseIsInEnglishWithoutATranslator(): void
    {
        $response = (new UnauthorizedResponseFactory())();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            [
                'status' => 401,
                'title' => 'Unauthorized',
                'detail' => 'The user is not authorized to access this resource.',
            ],
            json_decode((string) $response->getBody(), true)
        );
    }

    public function testTheResponseIsTranslatedWithATranslator(): void
    {
        $translator = TranslatorFactory::create('es', [], [new AuthTranslationResourceProvider()]);

        $response = (new UnauthorizedResponseFactory($translator))();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            [
                'status' => 401,
                'title' => 'No autorizado',
                'detail' => 'El usuario no está autorizado para acceder a este recurso.',
            ],
            json_decode((string) $response->getBody(), true)
        );
    }
}
