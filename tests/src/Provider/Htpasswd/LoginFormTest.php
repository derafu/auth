<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Htpasswd;

use Derafu\Auth\Provider\Htpasswd\Web\Form\LoginForm;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Factory\TranslatingFormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\Translation\TranslatorFactory;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The login form of the file has two fields, always the same, with fixed titles
 * that are translated when the form is created.
 */
#[CoversClass(LoginForm::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class LoginFormTest extends TestCase
{
    #[Test]
    public function theFieldsAreTheUsernameAndThePassword(): void
    {
        $definition = (new LoginForm())->getDefinition();

        Assert::assertIsArray($definition['schema']);
        Assert::assertIsArray($definition['schema']['properties']);
        $this->assertSame(['username', 'password'], array_keys($definition['schema']['properties']));
        Assert::assertIsArray($definition['schema']);
        $this->assertSame(['username', 'password'], $definition['schema']['required']);
        Assert::assertIsArray($definition['schema']);
        $this->assertSame('login', $definition['schema']['name']);
        Assert::assertIsArray($definition['options']);
        $this->assertTrue($definition['options']['captcha_protection']);
        // The definition is made once.
        $this->assertSame($definition, (new LoginForm())->getDefinition());
    }

    #[Test]
    public function theTitlesAreTranslatedWhenTheFormIsCreated(): void
    {
        $definition = (new LoginForm())->getDefinition();
        $create = fn (string $locale): array => (new TranslatingFormFactory(
            new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
            TranslatorFactory::create($locale, ['en'], [new AuthTranslationResourceProvider()])
        ))->create($definition)->toArray();

        $spanish = $create('es');
        $english = $create('en');

        Assert::assertIsArray($spanish['schema']);
        Assert::assertIsArray($spanish['schema']['properties']);
        Assert::assertIsArray($spanish['schema']['properties']['username']);
        $this->assertSame('Usuario', $spanish['schema']['properties']['username']['title']);
        Assert::assertIsArray($spanish['schema']);
        Assert::assertIsArray($spanish['schema']['properties']);
        Assert::assertIsArray($spanish['schema']['properties']['password']);
        $this->assertSame('Contraseña', $spanish['schema']['properties']['password']['title']);
        Assert::assertIsArray($english['schema']);
        Assert::assertIsArray($english['schema']['properties']);
        Assert::assertIsArray($english['schema']['properties']['username']);
        $this->assertSame('Username', $english['schema']['properties']['username']['title']);
        Assert::assertIsArray($english['schema']);
        Assert::assertIsArray($english['schema']['properties']);
        Assert::assertIsArray($english['schema']['properties']['password']);
        $this->assertSame('Password', $english['schema']['properties']['password']['title']);
    }
}
