<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;

/**
 * Counts failed authentication attempts and exposes the applicable login limits.
 *
 * Web and API consumers share the same counters for an identity and client
 * address. Clearing an identity's counter leaves the aggregate address counter.
 */
interface LoginThrottleInterface
{
    /**
     * Determines whether a login limit applies to an identity and client address.
     *
     * @param string $identity The attempted user identity.
     * @param string $address The client address or trusted client network.
     * @return bool True when an applicable counter is currently limited.
     * @throws ConfigurationException If no cache pool is configured.
     * @throws TranslatableInvalidArgumentException If cached counter data has an invalid type.
     */
    public function isLimited(string $identity, string $address): bool;

    /**
     * Returns how long the identity and client address must wait before retrying.
     *
     * @param string $identity The attempted user identity.
     * @param string $address The client address or trusted client network.
     * @return int Remaining seconds for the longest applicable limit, or zero
     * when authentication is not limited.
     * @throws ConfigurationException If no cache pool is configured.
     * @throws TranslatableInvalidArgumentException If cached counter data has an invalid type.
     */
    public function retryAfter(string $identity, string $address): int;

    /**
     * Records a failed login for the identity/address and aggregate address counters.
     *
     * @param string $identity The attempted user identity.
     * @param string $address The client address or trusted client network.
     * @throws ConfigurationException If no cache pool is configured.
     * @throws TranslatableInvalidArgumentException If cached counter data has an invalid type.
     */
    public function hit(string $identity, string $address): void;

    /**
     * Clears the identity/address counter after successful authentication.
     *
     * The aggregate address counter is preserved.
     *
     * @param string $identity The authenticated user identity.
     * @param string $address The client address or trusted client network.
     * @throws ConfigurationException If no cache pool is configured.
     */
    public function clear(string $identity, string $address): void;
}
