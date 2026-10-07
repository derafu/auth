<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Database;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Limits the failed attempts to log in, against someone that tries passwords.
 *
 * Failed attempts are counted in a window that starts with the first one and
 * lasts `lockSeconds`. The login is limited when the window has `maxAttempts`
 * failed attempts for the same identity from the same address, or five times as
 * many from the same address (whatever the identity), until the window ends.
 * A login that works clears the count of that identity and that address.
 *
 * The counts are in a PSR-6 cache pool, so they are shared by every request of
 * the application.
 */
class LoginThrottle
{
    /**
     * How many times more attempts an address can make, whatever the identity.
     */
    private const ADDRESS_FACTOR = 5;

    /**
     * Creates a new login throttle.
     *
     * @param CacheItemPoolInterface $cache Where the counts are.
     * @param int $maxAttempts The failed attempts for an identity and an address.
     * @param int $lockSeconds The seconds of the window, and so of the limit.
     */
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly int $maxAttempts = 5,
        private readonly int $lockSeconds = 900
    ) {
    }

    /**
     * Whether the login is limited for an identity from an address.
     */
    public function isLimited(string $identity, string $address): bool
    {
        return $this->retryAfter($identity, $address) > 0;
    }

    /**
     * The seconds until the login is not limited for an identity from an
     * address, or 0 if it is not limited.
     */
    public function retryAfter(string $identity, string $address): int
    {
        $seconds = 0;

        foreach ([
            [$this->identityKey($identity, $address), $this->maxAttempts],
            [$this->addressKey($address), $this->maxAttempts * self::ADDRESS_FACTOR],
        ] as [$key, $limit]) {
            $window = $this->window($key);
            if ($window !== null && $window['count'] >= $limit) {
                $seconds = max($seconds, $window['until'] - time());
            }
        }

        return max(0, $seconds);
    }

    /**
     * Counts a failed attempt for an identity from an address.
     */
    public function hit(string $identity, string $address): void
    {
        foreach ([$this->identityKey($identity, $address), $this->addressKey($address)] as $key) {
            $window = $this->window($key) ?? ['count' => 0, 'until' => time() + $this->lockSeconds];
            $window['count']++;

            $item = $this->cache->getItem($key);
            $item->set($window);
            $item->expiresAt(new \DateTimeImmutable('@' . $window['until']));
            $this->cache->save($item);
        }
    }

    /**
     * Clears the count of an identity from an address, after a login that works.
     * The count of the address stays: it is of everything that it tried.
     */
    public function clear(string $identity, string $address): void
    {
        $this->cache->deleteItem($this->identityKey($identity, $address));
    }

    /**
     * The window of failed attempts of a key, if it has not ended.
     *
     * @return array{count: int, until: int}|null
     */
    private function window(string $key): ?array
    {
        $item = $this->cache->getItem($key);
        if (!$item->isHit()) {
            return null;
        }

        $window = $item->get();

        return is_array($window) && $window['until'] > time() ? $window : null;
    }

    private function identityKey(string $identity, string $address): string
    {
        return 'auth_login_identity_' . hash('sha256', mb_strtolower(trim($identity)) . '|' . $address);
    }

    private function addressKey(string $address): string
    {
        return 'auth_login_address_' . hash('sha256', $address);
    }
}
