<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak\Api;

use Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;

/**
 * The scheme of the API of Keycloak: the access token that Keycloak gave to a
 * client, `Bearer`. A service (with `client_credentials`) and a person send the
 * same thing.
 *
 * The token is verified by what it says (see
 * `KeycloakTokenVerifier::verifyBearerToken()`): nothing is asked to Keycloak
 * but its keys, that are cached, so a request does not wait for it, unless the
 * introspection is on (it is, by default): then Keycloak is asked whether the
 * token is still active. The user has the roles of the realm and the ones of the
 * client of the audience.
 */
class KeycloakBearerScheme extends BearerScheme
{
    /**
     * Creates the scheme.
     *
     * @param KeycloakUserRepository $userRepository The user repository.
     * @param KeycloakConfiguration $config The configuration of Keycloak.
     */
    public function __construct(
        private readonly KeycloakUserRepository $userRepository,
        private readonly KeycloakConfiguration $config
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        $this->config->validateApi();
    }

    /**
     * {@inheritDoc}
     */
    protected function authenticateToken(string $token): ?UserInterface
    {
        try {
            return $this->userRepository->createUser(
                $this->userRepository->verifyBearerToken($token),
                $this->config->getApiAudience()
            );
        } catch (AuthenticationException) {
            return null;
        }
    }
}
