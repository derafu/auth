<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Abstract;

use Derafu\Auth\Abstract\AbstractProviderConfiguration;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Which paths need a user and which roles: a path is under a rule by segments
 * (`/api` is not `/apiary`), the rule that is more specific is the one that
 * counts, and the path and the rules are compared in their canonical form, so
 * the way a path is written does not decide whether it is protected.
 */
#[CoversClass(AbstractProviderConfiguration::class)]
#[UsesClass(HtpasswdConfiguration::class)]
#[UsesClass(ConfigurationException::class)]
final class ProtectedPathsTest extends TestCase
{
    /**
     * @param array<int|string, mixed> $paths
     */
    private function config(array $paths, bool $enabled = true): HtpasswdConfiguration
    {
        return new HtpasswdConfiguration(['enabled' => $enabled, 'protected_paths' => $paths]);
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function provideSegments(): array
    {
        // Path, whether the rule /api protects it.
        return [
            'the same path' => ['/api', true],
            'below it' => ['/api/index', true],
            'much below it' => ['/api/index/x/y', true],
            'a slash at the end' => ['/api/', true],
            'not a segment boundary' => ['/apiary', false],
            'not a segment boundary, below it' => ['/apiary/x', false],
            'a segment that starts the same' => ['/api2/x', false],
            'another path' => ['/other', false],
            'the root' => ['/', false],
            'a path that has the rule in the middle' => ['/x/api', false],
        ];
    }

    #[Test]
    #[DataProvider('provideSegments')]
    public function aRuleProtectsItsPathAndTheOnesBelowItBySegments(string $path, bool $protected): void
    {
        $config = $this->config(['/api']);

        $this->assertSame($protected, $config->requiresAuth($path));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function provideWaysOfWritingAProtectedPath(): array
    {
        return [
            'as it is' => ['/api/index'],
            'a double slash at the start' => ['//api/index'],
            'a double slash in the middle' => ['/api//index'],
            'many slashes' => ['///api////index//'],
            'a dot segment' => ['/api/./index'],
            'a dot segment at the end' => ['/api/index/.'],
            'a slash at the end' => ['/api/index/'],
            'an escaped letter' => ['/api/%69ndex'],
            'an escaped letter of the first segment' => ['/%61pi/index'],
            'an escaped dot segment' => ['/api/%2E/index'],
            'the case is different' => ['/API/Index'],
            'the case is different, escaped' => ['/%41PI/%49ndex'],
            'below it, written another way' => ['/api//index/./x'],
        ];
    }

    #[Test]
    #[DataProvider('provideWaysOfWritingAProtectedPath')]
    public function everyWayOfWritingAProtectedPathIsProtected(string $path): void
    {
        $config = $this->config(['/api/index' => ['admin']]);

        $this->assertTrue($config->requiresAuth($path), $path);
        $this->assertSame(['admin'], $config->allowedRoles($path), $path);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function provideWaysOfWritingARule(): array
    {
        return [
            'as it is' => ['/api'],
            'a slash at the end' => ['/api/'],
            'no slash at the start' => ['api'],
            'many slashes' => ['//api//'],
            'a dot segment' => ['/./api'],
            'an escaped letter' => ['/%61pi'],
            'the case' => ['/API'],
        ];
    }

    #[Test]
    #[DataProvider('provideWaysOfWritingARule')]
    public function everyWayOfWritingARuleProtectsTheSamePaths(string $rule): void
    {
        $config = $this->config([$rule => ['admin']]);

        $this->assertTrue($config->requiresAuth('/api'));
        $this->assertTrue($config->requiresAuth('/api/x'));
        $this->assertFalse($config->requiresAuth('/apiary'));
        $this->assertSame(['admin'], $config->allowedRoles('/api/x'));
    }

    #[Test]
    public function theMostSpecificRuleIsTheOneThatCountsWhateverTheOrder(): void
    {
        $general = ['/api' => ['api']];
        $specific = ['/api/human_resources' => ['rrhh']];

        foreach ([$general + $specific, $specific + $general] as $paths) {
            $config = $this->config($paths);

            $this->assertSame(['rrhh'], $config->allowedRoles('/api/human_resources'));
            $this->assertSame(['rrhh'], $config->allowedRoles('/api/human_resources/x/y'));
            $this->assertSame(['api'], $config->allowedRoles('/api/billing'));
            $this->assertSame(['api'], $config->allowedRoles('/api'));
            // Not a segment boundary: it is only under /api.
            $this->assertSame(['api'], $config->allowedRoles('/api/human_resourcesX'));
            $this->assertSame([], $config->allowedRoles('/other'));
        }
    }

    #[Test]
    public function aRuleBelowAnotherOneCanNeedNoRolesAndThenNoneIsNeeded(): void
    {
        // Under /private only a user is needed, except under /private/admin.
        $config = $this->config(['/private/admin' => 'admin', '/private']);

        $this->assertSame([], $config->allowedRoles('/private/page'));
        $this->assertSame(['admin'], $config->allowedRoles('/private/admin/users'));
        $this->assertTrue($config->requiresAuth('/private/page'));

        // The other way: roles for all of it, nothing below.
        $config = $this->config(['/private' => ['staff'], '/private/open']);
        $this->assertSame(['staff'], $config->allowedRoles('/private/page'));
        $this->assertSame([], $config->allowedRoles('/private/open/page'));
        $this->assertTrue($config->requiresAuth('/private/open/page'));
    }

    #[Test]
    public function theRootProtectsEverythingAndAMoreSpecificRuleBeatsIt(): void
    {
        $config = $this->config(['/' => ['user'], '/admin' => ['admin']]);

        foreach (['/', '/page', '/a/b/c', '//x', '/admin'] as $path) {
            $this->assertTrue($config->requiresAuth($path), $path);
        }
        $this->assertSame(['user'], $config->allowedRoles('/page'));
        $this->assertSame(['user'], $config->allowedRoles('/'));
        $this->assertSame(['admin'], $config->allowedRoles('/admin/users'));
        $this->assertSame(['user'], $config->allowedRoles('/administrator'));
    }

    #[Test]
    public function twoRulesWithTheSamePathAreResolvedByTheFirstOne(): void
    {
        $config = $this->config(['/api' => ['first'], '/api/' => ['second']]);

        $this->assertSame(['first'], $config->allowedRoles('/api/x'));
    }

    #[Test]
    public function aPathWithoutASafeFormNeedsAUserAndNoRole(): void
    {
        // It can not be told which rule it is under, so it is not let in without a
        // user (the router refuses it before: this is the second wall).
        $config = $this->config(['/admin' => ['admin']]);

        foreach (['/admin/../x', '/x/../../admin', '/a%2Fb', '/a%5Cb', "/a\0b", '/a%00b', '/a/%2e%2e/b'] as $path) {
            $this->assertTrue($config->requiresAuth($path), $path);
            $this->assertSame([], $config->allowedRoles($path), $path);
        }
    }

    #[Test]
    public function nothingIsProtectedWhenTheAuthenticationIsDisabled(): void
    {
        $config = $this->config(['/api' => ['admin'], '/'], enabled: false);

        $this->assertFalse($config->requiresAuth('/api/x'));
        $this->assertFalse($config->requiresAuth('/a/../b'));
        $this->assertSame([], $config->allowedRoles('/api/x'));
    }

    #[Test]
    public function aPathThatIsNotUnderAnyRuleIsPublic(): void
    {
        $config = $this->config(['/academy', '/api/billing' => ['billing']]);

        foreach (['/', '/public', '/academyx', '/api', '/api/billingx', '/apiary'] as $path) {
            $this->assertFalse($config->requiresAuth($path), $path);
            $this->assertSame([], $config->allowedRoles($path), $path);
        }
    }

    #[Test]
    public function theProtectedPathsAreGivenAsTheyWereConfigured(): void
    {
        $config = $this->config(['/api/', 'other' => 'admin', '/staff' => ['a', 'b']]);

        $this->assertSame(['/api/' => [], 'other' => ['admin'], '/staff' => ['a', 'b']], $config->getProtectedPaths());
    }

    /**
     * @return array<string, array{int|string|array<mixed>|null}>
     */
    public static function provideRulesThatAreNotPaths(): array
    {
        return [
            'empty' => [''],
            'spaces' => ['   '],
            'a parent segment' => ['/a/../b'],
            'an escaped slash' => ['/a%2Fb'],
            'an escaped backslash' => ['/a%5Cb'],
            'a backslash' => ['/a\\b'],
            'a null byte' => ["/a\0b"],
            'an escape that is not valid' => ['/a%zz'],
            'a number' => [5],
            'an array' => [['/a']],
            'null' => [null],
        ];
    }

    /**
     * @param int|string|array<mixed>|null $rule
     */
    #[Test]
    #[DataProvider('provideRulesThatAreNotPaths')]
    public function aRuleThatIsNotAPathIsAnErrorOfTheConfiguration(int|string|array|null $rule): void
    {
        try {
            $this->config(['/public-rule', $rule]);
            $this->fail('The rule was accepted.');
        } catch (ConfigurationException $e) {
            $this->assertStringContainsString('is not valid', $e->getMessage());
        }
    }

    #[Test]
    public function aRuleWithRolesThatIsNotAPathIsAnErrorToo(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The protected path "/a/../b" is not valid.');

        $this->config(['/a/../b' => ['admin']]);
    }
}
