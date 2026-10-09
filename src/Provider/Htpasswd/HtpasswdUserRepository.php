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
 * The roles of the users are in a second file, the group file (`.htgroup`, the
 * one of `AuthGroupFile` of Apache, see `HtpasswdConfiguration::getGroupPath()`):
 * a line is `role: identity identity...`, and the blank lines and the ones that
 * start with `#` are ignored. A user that is in a group and not in the
 * `.htpasswd` is not a user, so it is ignored too. Without a group file the users
 * have no roles, and they have no details.
 *
 * The files are read every time they are needed, so a change in them is what the
 * next request sees. A user that does not exist takes as long as one that does (the
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

        return $this->userFactory->create($credential, $this->rolesOf($credential));
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
            ? $this->userFactory->create($identity, $this->rolesOf($identity))
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
     * The roles of a user: the groups of the group file that have it.
     *
     * @return list<string>
     * @throws ConfigurationException If there is a group file and it can not be
     * read: a user does not go in with fewer roles than the ones it has.
     */
    private function rolesOf(string $identity): array
    {
        $path = $this->config->getGroupPath();
        if ($path === '') {
            return [];
        }

        $lines = is_file($path) ? @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : false;
        if ($lines === false) {
            throw new ConfigurationException([
                'The group file "{path}" can not be read.',
                'path' => $path,
            ]);
        }

        $roles = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || !str_contains($line, ':')) {
                continue;
            }

            [$role, $members] = explode(':', $line, 2);
            $role = trim($role);
            if ($role !== '' && in_array($identity, preg_split('/\s+/', trim($members)) ?: [], true)) {
                $roles[] = $role;
            }
        }

        return array_values(array_unique($roles));
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
