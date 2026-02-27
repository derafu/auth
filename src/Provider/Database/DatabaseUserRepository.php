<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Database;

use Closure;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\UserRepositoryInterface;
use Derafu\Auth\User;
use Derafu\Auth\UserFactory;
use Mezzio\Authentication\UserRepository\PdoDatabase;
use PDO;

/**
 * Database user repository implementation.
 *
 * This repository handles user authentication through database.
 */
class DatabaseUserRepository implements UserRepositoryInterface
{
    /**
     * The PDO instance.
     *
     * @var PDO
     */
    private PDO $pdo;

    /**
     * The user factory.
     *
     * @var Closure
     */
    private Closure $authUserFactory;

    /**
     * The provider.
     *
     * This is the UserRepositoryInterface implementation from Mezzio for using
     * PdoDatabase as backend.
     *
     * @var PdoDatabase
     */
    private PdoDatabase $provider;

    /**
     * Creates a new Database user repository.
     *
     * @param DatabaseConfiguration $config The Database configuration.
     */
    public function __construct(
        private readonly DatabaseConfiguration $config
    ) {
        $this->pdo = new PDO($this->config->getDatabaseUrl());
        $config = $this->config->getUserRepository();
        $this->authUserFactory = (new UserFactory())();
        $this->provider = new PdoDatabase($this->pdo, $config, $this->authUserFactory);
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(string $credential, ?string $password = null): ?UserInterface
    {
        $mezzioUser = $this->provider->authenticate($credential, $password);
        if ($mezzioUser === null) {
            return null;
        }

        return new User(
            $mezzioUser->getIdentity(),
            $mezzioUser->getRoles(),
            $mezzioUser->getDetails()
        );
    }
}
