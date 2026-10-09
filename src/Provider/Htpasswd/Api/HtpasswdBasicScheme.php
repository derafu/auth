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
use Derafu\Auth\Authentication\LoginThrottle;
use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;
use Derafu\Auth\Provider\Htpasswd\HtpasswdUserRepository;

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
     * @param HtpasswdUserRepository $userRepository Where the users are.
     * @param HtpasswdConfiguration $config The configuration of the provider.
     * @param LoginThrottle|null $throttle Limits the failed attempts. Without it
     * they are not limited.
     */
    public function __construct(
        HtpasswdUserRepository $userRepository,
        private readonly HtpasswdConfiguration $config,
        ?LoginThrottle $throttle = null
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
