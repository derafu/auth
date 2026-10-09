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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

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
}
