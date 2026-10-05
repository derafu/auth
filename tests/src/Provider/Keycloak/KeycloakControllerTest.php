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

use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakController;
use Derafu\Auth\Provider\Keycloak\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Translation\TranslatorFactory;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The description that Keycloak gives when it reports an error is not ours: it is
 * the message of the exception as it comes, and it is never translated.
 */
#[CoversClass(KeycloakController::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class KeycloakControllerTest extends TestCase
{
    public function testTheDescriptionOfKeycloakIsTheMessageOfTheExceptionAsItComes(): void
    {
        $controller = new KeycloakController(
            $this->createStub(KeycloakConfiguration::class),
            $this->createStub(KeycloakUserRepository::class),
            $this->createStub(KeycloakSessionManager::class)
        );
        $request = (new ServerRequest())->withQueryParams(['error_description' => 'Invalid user credentials {x}']);

        try {
            $controller->handle($request);
            $this->fail('The error of Keycloak was not an exception.');
        } catch (AuthenticationException $e) {
            $translator = TranslatorFactory::create('es', [], [new AuthTranslationResourceProvider()]);

            $this->assertSame(400, $e->getCode());
            $this->assertSame('Invalid user credentials {x}', $e->getMessage());
            $this->assertSame('Invalid user credentials {x}', $e->trans($translator));
            $this->assertSame(
                ['message' => 'Invalid user credentials {x}'],
                $e->getTranslatableMessage()->getParameters()
            );
        }
    }
}
