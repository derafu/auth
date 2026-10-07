<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Htpasswd;

use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\UserRepositoryInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\UserFactory;

/**
 * User repository over an `.htpasswd` file.
 *
 * A line of the file is `identity:hash`. Only the hashes of bcrypt are accepted
 * (`htpasswd -B`, which writes `$2y$`): a line with any other hash (`apr1`,
 * `{SHA}`, `crypt`) is ignored, as if the user was not in the file. So are the
 * blank lines and the ones that start with `#`.
 *
 * The file only says who the user is: the user has no roles and no details. The
 * file is read every time it is needed, so a change in it is what the next
 * request sees. A user that does not exist takes as long as one that does (the
 * password is verified against a hash anyway), so the time it takes does not say
 * which identities exist.
 */
class HtpasswdUserRepository implements UserRepositoryInterface
{
    /**
     * The hash that is verified when the user does not exist.
     */
    private static ?string $unknownUserHash = null;

    private readonly UserFactoryInterface $userFactory;

    /**
     * Creates a new htpasswd user repository.
     *
     * @param HtpasswdConfiguration $config The htpasswd configuration.
     * @param UserFactoryInterface|null $userFactory Makes the users. The default
     * one makes a `User`.
     */
    public function __construct(
        private readonly HtpasswdConfiguration $config,
        ?UserFactoryInterface $userFactory = null
    ) {
        $this->userFactory = $userFactory ?? new UserFactory();
    }

    /**
     * {@inheritDoc}
     *
     * @throws ConfigurationException If the file can not be read.
     */
    public function authenticate(string $credential, ?string $password = null): ?UserInterface
    {
        $hash = $this->read()[$credential] ?? null;

        // The same work for a user that does not exist.
        if ($hash === null) {
            password_verify($password ?? '', self::unknownUserHash());

            return null;
        }

        if ($password === null || !password_verify($password, $hash)) {
            return null;
        }

        return $this->userFactory->create($credential);
    }

    /**
     * Finds a user by its identity: it is what a session does to know whether
     * its user is still in the file. The password is not asked (the user already
     * logged in).
     *
     * @param string $identity The identity of the user.
     * @return UserInterface|null The user, or null if it is not in the file.
     * @throws ConfigurationException If the file can not be read.
     */
    public function find(string $identity): ?UserInterface
    {
        return isset($this->read()[$identity])
            ? $this->userFactory->create($identity)
            : null
        ;
    }

    /**
     * The users of the file, by identity, with their hash.
     *
     * @return array<string, string>
     * @throws ConfigurationException If the file can not be read.
     */
    private function read(): array
    {
        $path = $this->config->getHtpasswdPath();
        $lines = is_file($path) ? @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : false;
        if ($lines === false) {
            throw new ConfigurationException([
                'The htpasswd file "{path}" can not be read.',
                'path' => $path,
            ]);
        }

        $users = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || !str_contains($line, ':')) {
                continue;
            }

            [$identity, $hash] = explode(':', $line, 2);
            if (preg_match('/^\$2[aby]\$/', $hash)) {
                $users[$identity] = $hash;
            }
        }

        return $users;
    }

    /**
     * The hash of a password that no user has, to verify when the user does not
     * exist: made once, with the current algorithm.
     */
    private static function unknownUserHash(): string
    {
        return self::$unknownUserHash ??= password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
    }
}
