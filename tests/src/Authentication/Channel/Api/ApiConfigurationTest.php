<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authentication\Channel\Api;

use Derafu\Auth\Authentication\Channel\Api\ApiConfiguration;
use Derafu\Auth\Exception\ConfigurationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The paths of the API (where a client is authenticated by the credentials of the
 * header, without a session) and the label of its protection space.
 */
#[CoversClass(ApiConfiguration::class)]
#[UsesClass(ConfigurationException::class)]
final class ApiConfigurationTest extends TestCase
{
    /**
     * @param array<string, mixed> $config
     */
    private function config(array $config = []): ApiConfiguration
    {
        return new ApiConfiguration($config);
    }

    #[Test]
    public function theApiIsApiWithTheRealmApiByDefault(): void
    {
        $config = $this->config();

        $this->assertSame(['/api'], $config->getPaths());
        $this->assertSame('API', $config->getRealm());
    }

    #[Test]
    public function thePathsOfTheApiAreKeptInTheirCanonicalForm(): void
    {
        $config = $this->config(['paths' => ['/api/', 'v1', '//docs//index.json', '/%61dmin/./x']]);

        $this->assertSame(['/api', '/v1', '/docs/index.json', '/admin/x'], $config->getPaths());
    }

    #[Test]
    public function aPathOfTheApiCanBeGivenAsAText(): void
    {
        $this->assertSame(['/v1'], $this->config(['paths' => '/v1'])->getPaths());
    }

    #[Test]
    public function thereCanBeNoPathsOfTheApi(): void
    {
        // An application that has no API.
        $this->assertSame([], $this->config(['paths' => []])->getPaths());
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function providePathsThatAreNotOfAnApi(): array
    {
        return [
            'empty' => [''],
            'spaces' => ['   '],
            'the root, that would make the whole site the API' => ['/'],
            'slashes only' => ['//'],
            'a parent segment' => ['/a/../b'],
            'an escaped slash' => ['/a%2Fb'],
            'a control character' => ["/a\0b"],
            'a number' => [5],
            'an array' => [['/a']],
            'null' => [null],
        ];
    }

    #[Test]
    #[DataProvider('providePathsThatAreNotOfAnApi')]
    public function aPathThatIsNotValidIsAnErrorOfTheConfiguration(mixed $path): void
    {
        try {
            $this->config(['paths' => ['/ok', $path]]);
            $this->fail('The path was accepted.');
        } catch (ConfigurationException $e) {
            $this->assertStringContainsString('The path of the API', $e->getMessage());
        }
    }

    #[Test]
    public function theRealmIsATextWithoutTheCharactersThatWouldEndItsQuotes(): void
    {
        $this->assertSame('Billing API v2', $this->config(['realm' => 'Billing API v2'])->getRealm());
        $this->assertSame('Facturación', $this->config(['realm' => ' Facturación '])->getRealm());
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function provideRealmsThatAreNotValid(): array
    {
        return [
            'empty' => [''],
            'spaces' => ['   '],
            'a quote' => ['Bill"ing'],
            'a quote and a header' => ['a", error="x'],
            'a backslash' => ['Bill\\ing'],
            'a new line' => ["Billing\nSet-Cookie: x=1"],
            'a carriage return' => ["Billing\rx"],
            'a null byte' => ["Bill\0ing"],
            'a delete' => ["Bill\x7fing"],
            'a number' => [5],
            'an array' => [['API']],
        ];
    }

    #[Test]
    #[DataProvider('provideRealmsThatAreNotValid')]
    public function aRealmThatCouldBreakTheHeaderIsAnErrorOfTheConfiguration(mixed $realm): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The realm of the API must be a text without quotes, backslashes or control characters.');

        $this->config(['realm' => $realm]);
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function provideApiPaths(): array
    {
        return [
            'the same path' => ['/api', true],
            'below it' => ['/api/items', true],
            'much below it' => ['/api/items/1/x', true],
            'not a segment boundary' => ['/apiary', false],
            'another path' => ['/dashboard', false],
            'the root' => ['/', false],
            'it is written another way' => ['/api//items', true],
            'a path that has no safe form' => ['/api/../x', false],
        ];
    }

    #[Test]
    #[DataProvider('provideApiPaths')]
    public function aPathIsOfTheApiWhenItIsOneOfThemOrBelowIt(string $path, bool $isApi): void
    {
        $this->assertSame($isApi, $this->config()->isApiPath($path));
    }

    #[Test]
    public function theApiCanBeInSeveralPaths(): void
    {
        $config = $this->config(['paths' => ['/api', '/v2']]);

        $this->assertTrue($config->isApiPath('/v2/items'));
        $this->assertTrue($config->isApiPath('/api/items'));
        $this->assertFalse($config->isApiPath('/v3/items'));
    }

    #[Test]
    public function withoutPathsNothingIsOfTheApi(): void
    {
        $this->assertFalse($this->config(['paths' => []])->isApiPath('/api/items'));
    }
}
