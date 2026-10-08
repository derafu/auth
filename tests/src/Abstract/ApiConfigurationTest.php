<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Abstract;

use Derafu\Auth\Abstract\AbstractProviderConfiguration;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The paths of the API (where a client is authenticated by the credentials of the
 * header, without a session) and the label of its protection space.
 */
#[CoversClass(AbstractProviderConfiguration::class)]
#[UsesClass(HtpasswdConfiguration::class)]
#[UsesClass(ConfigurationException::class)]
final class ApiConfigurationTest extends TestCase
{
    /**
     * @param array<string, mixed> $config
     */
    private function config(array $config = []): HtpasswdConfiguration
    {
        return new HtpasswdConfiguration($config);
    }

    #[Test]
    public function theApiIsApiWithTheRealmApiByDefault(): void
    {
        $config = $this->config();

        $this->assertSame(['/api'], $config->getApiPaths());
        $this->assertSame('API', $config->getApiRealm());
        $this->assertSame(['/api'], $config->get('api_paths'));
        $this->assertSame('API', $config->get('api_realm'));
        $this->assertSame(['/api'], $config->toArray()['api_paths']);
        $this->assertSame('API', $config->toArray()['api_realm']);
    }

    #[Test]
    public function thePathsOfTheApiAreKeptInTheirCanonicalForm(): void
    {
        $config = $this->config(['api_paths' => ['/api/', 'v1', '//docs//index.json', '/%61dmin/./x']]);

        $this->assertSame(['/api', '/v1', '/docs/index.json', '/admin/x'], $config->getApiPaths());
    }

    #[Test]
    public function aPathOfTheApiCanBeGivenAsAText(): void
    {
        $this->assertSame(['/v1'], $this->config(['api_paths' => '/v1'])->getApiPaths());
    }

    #[Test]
    public function thereCanBeNoPathsOfTheApi(): void
    {
        // An application that has no API.
        $this->assertSame([], $this->config(['api_paths' => []])->getApiPaths());
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
            $this->config(['api_paths' => ['/ok', $path]]);
            $this->fail('The path was accepted.');
        } catch (ConfigurationException $e) {
            $this->assertStringContainsString('The path of the API', $e->getMessage());
        }
    }

    #[Test]
    public function theRealmIsATextWithoutTheCharactersThatWouldEndItsQuotes(): void
    {
        $this->assertSame('Billing API v2', $this->config(['api_realm' => 'Billing API v2'])->getApiRealm());
        $this->assertSame('Facturación', $this->config(['api_realm' => ' Facturación '])->getApiRealm());
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

        $this->config(['api_realm' => $realm]);
    }
}
