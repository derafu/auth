<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth;

use FilesystemIterator;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * The messages tell the user which environment variable to set, so every name
 * that the code mentions must be one that the services files read: a message
 * that names a variable that does not exist (one that was renamed, for example)
 * sends the user to set something that does nothing.
 */
#[CoversNothing]
final class EnvironmentNamesTest extends TestCase
{
    /**
     * @return list<string> The names `AUTH_*` that the files of a directory mention.
     */
    private function names(string $directory, string $extension): array
    {
        $names = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS));
        foreach ($files as $file) {
            if ($file->getExtension() !== $extension) {
                continue;
            }
            preg_match_all('/\bAUTH_[A-Z0-9_]*[A-Z0-9]\b/', (string) file_get_contents($file->getPathname()), $matches);
            array_push($names, ...$matches[0]);
        }

        return array_values(array_unique($names));
    }

    #[Test]
    public function everyVariableThatTheCodeNamesIsReadByTheServices(): void
    {
        $root = dirname(__DIR__, 2);
        $read = $this->names($root . '/resources/config', 'yaml');

        $this->assertNotEmpty($read);
        $this->assertSame(
            [],
            array_values(array_diff($this->names($root . '/src', 'php'), $read)),
            'The code names variables that no services file reads.'
        );
    }
}
