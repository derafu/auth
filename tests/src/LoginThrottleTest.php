<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth;

use Derafu\Auth\Authentication\LoginThrottle;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * The failed attempts to log in are counted in a window: an identity from an
 * address has a few of them, and an address has more, whatever the identity.
 */
#[CoversClass(LoginThrottle::class)]
final class LoginThrottleTest extends TestCase
{
    private ArrayAdapter $cache;

    private LoginThrottle $throttle;

    protected function setUp(): void
    {
        $this->cache = new ArrayAdapter();
        $this->throttle = new LoginThrottle($this->cache, maxAttempts: 3, lockSeconds: 600);
    }

    private function failLogin(int $times, string $identity = 'ana@example.com', string $address = '203.0.113.7'): void
    {
        for ($i = 0; $i < $times; $i++) {
            $this->throttle->hit($identity, $address);
        }
    }

    #[Test]
    public function aLoginIsNotLimitedAtTheBeginning(): void
    {
        $this->assertFalse($this->throttle->isLimited('ana@example.com', '203.0.113.7'));
        $this->assertSame(0, $this->throttle->retryAfter('ana@example.com', '203.0.113.7'));
    }

    #[Test]
    public function itIsLimitedWhenTheFailedAttemptsOfAnIdentityAreTheMaximum(): void
    {
        $this->failLogin(2);
        $this->assertFalse($this->throttle->isLimited('ana@example.com', '203.0.113.7'));

        $this->failLogin(1);
        $this->assertTrue($this->throttle->isLimited('ana@example.com', '203.0.113.7'));
    }

    #[Test]
    public function theLimitLastsUntilTheWindowEnds(): void
    {
        $this->failLogin(3);

        $seconds = $this->throttle->retryAfter('ana@example.com', '203.0.113.7');

        // The window started with the first attempt and lasts ten minutes.
        $this->assertGreaterThan(590, $seconds);
        $this->assertLessThanOrEqual(600, $seconds);
    }

    #[Test]
    public function theWindowDoesNotStartAgainWithEachAttempt(): void
    {
        $this->failLogin(1);
        $key = array_values(array_filter(
            array_keys($this->itemsOf()),
            fn (string $key) => str_starts_with($key, 'auth_login_identity_')
        ))[0];
        $item = $this->cache->getItem($key);
        $item->set(['count' => 1, 'until' => time() + 100]);
        $this->cache->save($item);

        $this->failLogin(2);

        // Ten minutes from the first one would be 600: it is the 100 that it had.
        $this->assertLessThanOrEqual(100, $this->throttle->retryAfter('ana@example.com', '203.0.113.7'));
    }

    #[Test]
    public function aWindowThatEndedDoesNotLimit(): void
    {
        $this->failLogin(3);
        foreach (array_keys($this->itemsOf()) as $key) {
            $item = $this->cache->getItem($key);
            $item->set(['count' => 99, 'until' => time() - 1]);
            $this->cache->save($item);
        }

        $this->assertFalse($this->throttle->isLimited('ana@example.com', '203.0.113.7'));

        // And the next failure starts a new window.
        $this->failLogin(1);
        $this->assertFalse($this->throttle->isLimited('ana@example.com', '203.0.113.7'));
    }

    #[Test]
    public function anotherIdentityOrAnotherAddressIsNotLimited(): void
    {
        $this->failLogin(3);

        $this->assertFalse($this->throttle->isLimited('ben@example.com', '203.0.113.7'));
        $this->assertFalse($this->throttle->isLimited('ana@example.com', '198.51.100.9'));
    }

    #[Test]
    public function theIdentityIsTheSameWhateverItsCaseAndSpaces(): void
    {
        $this->failLogin(3);

        $this->assertTrue($this->throttle->isLimited('  ANA@Example.com ', '203.0.113.7'));
    }

    #[Test]
    public function anAddressIsLimitedWhateverTheIdentityWhenItTriedFiveTimesTheMaximum(): void
    {
        // 15 failures (5 times 3), each one of another identity.
        for ($i = 0; $i < 14; $i++) {
            $this->failLogin(1, 'user' . $i . '@example.com');
        }
        $this->assertFalse($this->throttle->isLimited('another@example.com', '203.0.113.7'));

        $this->failLogin(1, 'user14@example.com');

        $this->assertTrue($this->throttle->isLimited('another@example.com', '203.0.113.7'));
        $this->assertFalse($this->throttle->isLimited('another@example.com', '198.51.100.9'));
    }

    #[Test]
    public function aLoginThatWorksClearsTheCountOfThatIdentityButNotTheOneOfTheAddress(): void
    {
        $this->failLogin(3);

        $this->throttle->clear('ana@example.com', '203.0.113.7');

        $this->assertFalse($this->throttle->isLimited('ana@example.com', '203.0.113.7'));

        // The address still has its 3 failures: 12 more and it is limited.
        for ($i = 0; $i < 11; $i++) {
            $this->failLogin(1, 'user' . $i . '@example.com');
        }
        $this->assertFalse($this->throttle->isLimited('ana@example.com', '203.0.113.7'));

        for ($i = 11; $i < 12; $i++) {
            $this->failLogin(1, 'user' . $i . '@example.com');
        }
        $this->assertTrue($this->throttle->isLimited('ana@example.com', '203.0.113.7'));
    }

    /**
     * @return array<string, mixed>
     */
    private function itemsOf(): array
    {
        $items = [];
        foreach (['ana@example.com' => '203.0.113.7'] as $identity => $address) {
            foreach ([
                'auth_login_identity_' . hash('sha256', $identity . '|' . $address),
                'auth_login_address_' . hash('sha256', $address),
            ] as $key) {
                $items[$key] = $this->cache->getItem($key)->get();
            }
        }

        return array_filter($items);
    }
}
