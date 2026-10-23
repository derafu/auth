<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Htpasswd;

use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use stdClass;
use Stringable;

#[CoversClass(HtpasswdConfiguration::class)]
#[UsesClass(ConfigurationException::class)]
final class HtpasswdConfigurationTest extends TestCase
{
    /** @return iterable<string, array{string, mixed}> */
    public static function invalidPaths(): iterable
    {
        foreach (['htpasswd_path', 'group_path', 'project_dir'] as $key) {
            yield $key . ' as array' => [$key, []];
        }
        yield 'boolean path' => ['htpasswd_path', false];
        yield 'integer path' => ['htpasswd_path', 0];
        yield 'float path' => ['htpasswd_path', 1.5];
        yield 'object path' => ['htpasswd_path', new stdClass()];
        yield 'Stringable path' => ['htpasswd_path', new class () implements Stringable {
            public function __toString(): string
            {
                return '/etc/.htpasswd';
            }
        }];
        yield 'false project directory' => ['project_dir', false];
        yield 'integer zero project directory' => ['project_dir', 0];
    }

    #[DataProvider('invalidPaths')]
    public function testRejectsNonStringPathsBeforeUsingThem(string $key, mixed $value): void
    {
        $this->expectException(TranslatableInvalidArgumentException::class);
        $this->expectExceptionMessage('"' . $key . '"');

        new HtpasswdConfiguration([$key => $value]);
    }

    public function testMissingAndNullValuesKeepTheDefaults(): void
    {
        foreach ([[], ['htpasswd_path' => null, 'group_path' => null, 'project_dir' => null]] as $values) {
            $config = new HtpasswdConfiguration($values);
            $this->assertSame('', $config->getHtpasswdPath());
            $this->assertSame('', $config->getGroupPath());
        }
    }

    public function testReplacesTheProjectDirectoryInBothPaths(): void
    {
        $config = new HtpasswdConfiguration([
            'htpasswd_path' => '%kernel.project_dir%/etc/.htpasswd',
            'group_path' => '%kernel.project_dir%/etc/.htgroup',
            'project_dir' => '/srv/app',
        ]);
        $config->validate();

        $this->assertSame('/srv/app/etc/.htpasswd', $config->getHtpasswdPath());
        $this->assertSame('/srv/app/etc/.htgroup', $config->getGroupPath());
    }

    /** @return iterable<string, array{string|null}> */
    public static function emptyProjectDirectories(): iterable
    {
        yield 'null' => [null];
        yield 'empty string' => [''];
        yield 'string zero' => ['0'];
    }

    #[DataProvider('emptyProjectDirectories')]
    public function testEmptyProjectDirectoriesDoNotReplaceThePlaceholder(?string $directory): void
    {
        $config = new HtpasswdConfiguration([
            'htpasswd_path' => '%kernel.project_dir%/.htpasswd',
            'group_path' => '%kernel.project_dir%/.htgroup',
            'project_dir' => $directory,
        ]);

        $this->assertSame('%kernel.project_dir%/.htpasswd', $config->getHtpasswdPath());
        $this->assertSame('%kernel.project_dir%/.htgroup', $config->getGroupPath());
    }

    public function testAnEmptyHtpasswdPathStillFailsOnlyWhenValidated(): void
    {
        $config = new HtpasswdConfiguration(['htpasswd_path' => '']);
        $this->assertSame('', $config->getHtpasswdPath());

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The path of the htpasswd file is not configured: set AUTH_HTPASSWD_PATH.');
        $config->validate();
    }

    public function testStringZeroIsAPathAndTheGroupFileIsOptional(): void
    {
        $config = new HtpasswdConfiguration(['htpasswd_path' => '0', 'group_path' => '']);
        $config->validate();

        $this->assertSame('0', $config->getHtpasswdPath());
        $this->assertSame('', $config->getGroupPath());
    }
}
