<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authentication\Channel\Web;

use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use stdClass;
use Stringable;

/**
 * The paths of the web channel, and every how many seconds the session asks its
 * provider again.
 */
#[CoversClass(WebConfiguration::class)]
#[UsesClass(ConfigurationException::class)]
final class WebConfigurationTest extends TestCase
{
    #[Test]
    public function theDefaultsAreTheOnesOfASiteWithItsLoginInAPage(): void
    {
        $config = new WebConfiguration();

        $this->assertSame('/auth/login', $config->getLoginPath());
        $this->assertSame('/auth/logout', $config->getLogoutPath());
        $this->assertSame('/', $config->getLoginRedirectPath());
        $this->assertSame('/', $config->getLogoutRedirectPath());
        $this->assertSame('/', $config->getUnauthorizedRedirectPath());
        $this->assertNull($config->getRefreshInterval());
    }

    #[Test]
    public function everyPathCanBeConfigured(): void
    {
        $config = new WebConfiguration([
            'login_path' => '/in',
            'logout_path' => '/out',
            'login_redirect_path' => '/home',
            'logout_redirect_path' => '/bye',
            'unauthorized_redirect_path' => '/please-log-in',
            'refresh_interval' => 60,
        ]);

        $this->assertSame('/in', $config->getLoginPath());
        $this->assertSame('/out', $config->getLogoutPath());
        $this->assertSame('/home', $config->getLoginRedirectPath());
        $this->assertSame('/bye', $config->getLogoutRedirectPath());
        $this->assertSame('/please-log-in', $config->getUnauthorizedRedirectPath());
        $this->assertSame(60, $config->getRefreshInterval());
    }

    #[Test]
    public function zeroIsTheSameAsNotSayingAndTheProviderDecides(): void
    {
        $this->assertNull((new WebConfiguration(['refresh_interval' => 0]))->getRefreshInterval());
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function provideIntervalsThatAreNotValid(): array
    {
        return [
            'negative' => [-1],
            'a text' => ['60'],
            'a decimal' => [1.5],
            'true' => [true],
        ];
    }

    #[Test]
    #[DataProvider('provideIntervalsThatAreNotValid')]
    public function anIntervalThatIsNotAWholeNumberOfSecondsIsAnError(mixed $interval): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The refresh interval must be a number of seconds, 0 or more.');

        new WebConfiguration(['refresh_interval' => $interval]);
    }

    /** @return iterable<string, array{string, string, string}> */
    public static function paths(): iterable
    {
        yield 'login' => ['login_path', 'getLoginPath', '/auth/login'];
        yield 'logout' => ['logout_path', 'getLogoutPath', '/auth/logout'];
        yield 'after login' => ['login_redirect_path', 'getLoginRedirectPath', '/'];
        yield 'after logout' => ['logout_redirect_path', 'getLogoutRedirectPath', '/'];
        yield 'unauthorized' => ['unauthorized_redirect_path', 'getUnauthorizedRedirectPath', '/'];
    }

    #[DataProvider('paths')]
    public function testPathPrecedenceAndEmptyValuesRemainUnchanged(string $key, string $getter, string $fallback): void
    {
        $this->assertSame('/configured', (new WebConfiguration([$key => '/configured'], [$key => '/provider']))->$getter());
        $this->assertSame('/provider', (new WebConfiguration([], [$key => '/provider']))->$getter());
        $this->assertSame('/provider', (new WebConfiguration([$key => null], [$key => '/provider']))->$getter());
        $this->assertSame($fallback, (new WebConfiguration([$key => null], [$key => null]))->$getter());
        $this->assertSame('', (new WebConfiguration([$key => ''], [$key => '/provider']))->$getter());
        $this->assertSame('', (new WebConfiguration([], [$key => '']))->$getter());
        $this->assertSame('0', (new WebConfiguration([$key => '0']))->$getter());
        $this->assertSame('/configured', (new WebConfiguration([$key => '/configured'], [$key => []]))->$getter());
    }

    /** @return iterable<string, array{string, mixed, bool}> */
    public static function invalidPaths(): iterable
    {
        $values = [false, 0, 1.5, [], new stdClass()];
        $index = 0;
        foreach (self::paths() as [$key]) {
            $value = $values[$index++];
            yield $key . ' in configuration' => [$key, $value, false];
            yield $key . ' in provider defaults' => [$key, $value, true];
        }
        yield 'Stringable is not a string' => ['login_path', new class () implements Stringable {
            public function __toString(): string
            {
                return '/login';
            }
        }, false];
    }

    #[DataProvider('invalidPaths')]
    public function testRejectsNonStringEffectivePaths(string $key, mixed $value, bool $inDefaults): void
    {
        $this->expectException(TranslatableInvalidArgumentException::class);
        $this->expectExceptionMessage('"' . $key . '"');

        new WebConfiguration($inDefaults ? [] : [$key => $value], $inDefaults ? [$key => $value] : []);
    }
}
