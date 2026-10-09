<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;

/**
 * A real `.htpasswd` file, in the temporary directory, with users whose password
 * is hashed with bcrypt, as `htpasswd -B` does.
 */
final class HtpasswdFile
{
    private readonly string $path;

    /**
     * @param array<string, string> $users The password of each identity.
     */
    public function __construct(array $users = ['ana' => 'secret'])
    {
        $this->path = tempnam(sys_get_temp_dir(), 'auth-htpasswd-') ?: '';
        $this->write($users);
    }

    /**
     * Writes the file again with these users (a line of a user of another
     * format, or a comment, is added with `append()`).
     *
     * @param array<string, string> $users The password of each identity.
     */
    public function write(array $users): void
    {
        $lines = '';
        foreach ($users as $identity => $password) {
            $lines .= $identity . ':' . password_hash($password, PASSWORD_BCRYPT) . "\n";
        }
        file_put_contents($this->path, $lines);
    }

    /**
     * Adds a line as it is.
     */
    public function append(string $line): void
    {
        file_put_contents($this->path, $line . "\n", FILE_APPEND);
    }

    public function path(): string
    {
        return $this->path;
    }

    /**
     * @param array<string, mixed> $config
     */
    public function config(array $config = []): HtpasswdConfiguration
    {
        return Stack::htpasswdConfiguration($config + ['htpasswd_path' => $this->path]);
    }

    public function remove(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }
}
