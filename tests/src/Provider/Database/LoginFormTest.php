<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Database;

use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\Web\Form\LoginForm;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Factory\TranslatingFormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\Stack;
use Derafu\Translation\TranslatorFactory;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The login form has the fields of the columns that are configured, with fixed
 * titles that are translated when the form is created.
 */
#[CoversClass(LoginForm::class)]
#[UsesClass(DatabaseConfiguration::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class LoginFormTest extends TestCase
{
    /**
     * @param array<string, string> $fields
     * @return array<string, mixed>
     */
    private function definition(array $fields = []): array
    {
        $config = Stack::databaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => ['field' => $fields],
        ]);

        return (new LoginForm($config))->getDefinition();
    }

    /**
     * @param array<string, mixed> $definition
     * @return array<string, mixed>
     */
    private function form(array $definition, string $locale): array
    {
        $translator = TranslatorFactory::create($locale, ['en'], [new AuthTranslationResourceProvider()]);

        return (new TranslatingFormFactory(
            new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
            $translator
        ))->create($definition)->toArray();
    }

    #[Test]
    public function theFieldsAreTheColumnsThatAreConfigured(): void
    {
        $default = $this->definition();
        $custom = $this->definition(['identity' => 'rut', 'password' => 'clave']);

        Assert::assertIsArray($default['schema']);
        Assert::assertIsArray($default['schema']['properties']);
        $this->assertSame(['email', 'password'], array_keys($default['schema']['properties']));
        Assert::assertIsArray($custom['schema']);
        Assert::assertIsArray($custom['schema']['properties']);
        $this->assertSame(['rut', 'clave'], array_keys($custom['schema']['properties']));
        Assert::assertIsArray($custom['schema']);
        $this->assertSame(['rut', 'clave'], $custom['schema']['required']);
    }

    #[Test]
    public function theTitlesDoNotDependOnTheNamesOfTheColumns(): void
    {
        // They used to be the name of the column with its first letter in
        // capitals ("Rut", "Clave").
        $custom = $this->definition(['identity' => 'user_login', 'password' => 'password_hash']);

        Assert::assertIsArray($custom['schema']);
        Assert::assertIsArray($custom['schema']['properties']);
        Assert::assertIsArray($custom['schema']['properties']['user_login']);
        $this->assertSame('Username', $custom['schema']['properties']['user_login']['title']);
        Assert::assertIsArray($custom['schema']);
        Assert::assertIsArray($custom['schema']['properties']);
        Assert::assertIsArray($custom['schema']['properties']['password_hash']);
        $this->assertSame('Password', $custom['schema']['properties']['password_hash']['title']);
    }

    #[Test]
    public function theTitlesAreTranslatedWhenTheFormIsCreated(): void
    {
        $definition = $this->definition(['identity' => 'rut', 'password' => 'clave']);

        $spanish = $this->form($definition, 'es');
        $english = $this->form($definition, 'en');

        Assert::assertIsArray($spanish['schema']);
        Assert::assertIsArray($spanish['schema']['properties']);
        Assert::assertIsArray($spanish['schema']['properties']['rut']);
        $this->assertSame('Usuario', $spanish['schema']['properties']['rut']['title']);
        Assert::assertIsArray($spanish['schema']);
        Assert::assertIsArray($spanish['schema']['properties']);
        Assert::assertIsArray($spanish['schema']['properties']['clave']);
        $this->assertSame('Contraseña', $spanish['schema']['properties']['clave']['title']);
        Assert::assertIsArray($english['schema']);
        Assert::assertIsArray($english['schema']['properties']);
        Assert::assertIsArray($english['schema']['properties']['rut']);
        $this->assertSame('Username', $english['schema']['properties']['rut']['title']);
        Assert::assertIsArray($english['schema']);
        Assert::assertIsArray($english['schema']['properties']);
        Assert::assertIsArray($english['schema']['properties']['clave']);
        $this->assertSame('Password', $english['schema']['properties']['clave']['title']);
    }
}
