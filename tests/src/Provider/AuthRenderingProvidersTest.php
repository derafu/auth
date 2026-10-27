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

use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Provider\AuthExtensionProvider;
use Derafu\Auth\Provider\AuthTemplatePathProvider;
use Derafu\Auth\Twig\AuthExtension;
use Derafu\Twig\Service\TwigCreator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthExtensionProvider::class)]
#[CoversClass(AuthTemplatePathProvider::class)]
#[UsesClass(AuthExtension::class)]
#[UsesClass(WebConfiguration::class)]
final class AuthRenderingProvidersTest extends TestCase
{
    #[Test]
    public function providersExposeAuthTemplatesAndFunctionsUsingTheConsumersConfiguration(): void
    {
        $configuration = new WebConfiguration([
            'login_path' => '/sign-in',
            'logout_path' => '/sign-out',
        ]);
        $twig = (new TwigCreator(
            ['extra' => false],
            extensionProviders: [new AuthExtensionProvider($configuration)],
            templatePathProvider: new AuthTemplatePathProvider(),
        ))->create();
        $twig->enableStrictVariables();

        self::assertTrue($twig->getLoader()->exists('auth/login.html.twig'));
        self::assertTrue($twig->getLoader()->exists('auth/profile.html.twig'));
        self::assertSame(
            '/sign-in|/sign-out|/auth/profile|no',
            $twig->createTemplate("{{ login_path() }}|{{ logout_path() }}|{{ profile_path() }}|{{ is_granted('admin') ? 'yes' : 'no' }}")->render(),
        );
    }
}
