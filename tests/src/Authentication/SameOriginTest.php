<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authentication;

use Derafu\Auth\Authentication\SameOrigin;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A request that changes something is only for the site itself, by what the
 * browser says: a request of another site (a cross-site request forgery) is not.
 */
#[CoversClass(SameOrigin::class)]
final class SameOriginTest extends TestCase
{
    /**
     * @param array<string, string> $headers
     */
    private function request(array $headers): ServerRequest
    {
        return new ServerRequest([], [], 'https://app.test/auth/logout', 'POST', 'php://input', $headers);
    }

    /**
     * @return array<string, array{array<string, string>, bool}>
     */
    public static function provideRequests(): array
    {
        return [
            'the browser says it is the same origin' => [['Sec-Fetch-Site' => 'same-origin'], true],
            'the user typed it' => [['Sec-Fetch-Site' => 'none'], true],
            'another site' => [['Sec-Fetch-Site' => 'cross-site'], false],
            'a subdomain is another site' => [['Sec-Fetch-Site' => 'same-site'], false],
            'the origin is the site' => [['Origin' => 'https://app.test'], true],
            'the origin is the site with its port' => [['Origin' => 'https://app.test:443'], true],
            'the origin is another host' => [['Origin' => 'https://evil.test'], false],
            'the origin is another scheme' => [['Origin' => 'http://app.test'], false],
            'the origin is another port' => [['Origin' => 'https://app.test:8443'], false],
            'it is not a browser: it says nothing' => [[], true],
            'what the browser says first counts' => [['Sec-Fetch-Site' => 'cross-site', 'Origin' => 'https://app.test'], false],
        ];
    }

    /**
     * @param array<string, string> $headers
     */
    #[Test]
    #[DataProvider('provideRequests')]
    public function itSaysWhetherTheRequestIsOfTheSite(array $headers, bool $expected): void
    {
        $this->assertSame($expected, SameOrigin::of($this->request($headers)));
    }
}
