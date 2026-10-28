<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Htpasswd\Api;

use Derafu\Auth\Authentication\Channel\Api\Scheme\BasicScheme;
use Derafu\Auth\Contract\HtpasswdConfigurationInterface;
use Derafu\Auth\Contract\LoginThrottleInterface;
use Derafu\Auth\Contract\PasswordUserRepositoryInterface;

/**
 * The scheme of the API of the htpasswd provider: `Basic`, the user and the
 * password of a client, verified against the `.htpasswd` file with the same limit of failed
 * attempts as the login form.
 */
class HtpasswdBasicScheme extends BasicScheme
{
    /**
     * Creates the scheme.
     *
     * @param PasswordUserRepositoryInterface $userRepository Where the users are.
     * @param HtpasswdConfigurationInterface $config The configuration of the provider.
     * @param LoginThrottleInterface|null $throttle Limits the failed attempts. Without it
     * they are not limited.
     */
    public function __construct(
        PasswordUserRepositoryInterface $userRepository,
        private readonly HtpasswdConfigurationInterface $config,
        ?LoginThrottleInterface $throttle = null
    ) {
        parent::__construct($userRepository, $throttle);
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        $this->config->validate();
    }
}
