<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth;

use Derafu\Array\Exception\TypeMismatchException as ArrayTypeMismatchException;
use Derafu\Auth\Authentication\Channel\Web\SessionManager;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use Derafu\Value\Exception\TypeMismatchException as ValueTypeMismatchException;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;
use Stringable;

/**
 * The session keeps the user as it was when the provider was asked, and when
 * that was: a session is asked again after the interval, not before.
 */
#[CoversClass(SessionManager::class)]
final class SessionManagerTest extends TestCase
{
    #[Test]
    public function theTimeOfTheCheckIsTheTimeTheUserWasStored(): void
    {
        $session = new Session([]);

        (new SessionManager())->storeUserInfo($session, ['identity' => 'ana']);

        $this->assertEqualsWithDelta(time(), $session->get('auth_checked_at'), 2);
    }

    #[Test]
    public function aSessionIsDueWhenTheIntervalPassedSinceTheCheck(): void
    {
        $manager = new SessionManager();
        $session = new Session([]);
        $manager->storeUserInfo($session, ['identity' => 'ana']);

        $this->assertFalse($manager->isRefreshDue($session, 300));

        $session->set('auth_checked_at', time() - 299);
        $this->assertFalse($manager->isRefreshDue($session, 300));
        $session->set('auth_checked_at', time() - 300);
        $this->assertTrue($manager->isRefreshDue($session, 300));
    }

    #[Test]
    public function aSessionWithoutTheTimeOfTheCheckIsDue(): void
    {
        // One that was made before the time was kept.
        $session = new Session(['user' => ['identity' => 'ana']]);

        $this->assertTrue((new SessionManager())->isRefreshDue($session, 300));
        $this->assertTrue((new SessionManager())->isRefreshDue($session, null));
    }

    #[Test]
    public function aSessionThatForgetsTheCheckIsDueAtOnce(): void
    {
        $manager = new SessionManager();
        $session = new Session([]);
        $manager->storeUserInfo($session, ['identity' => 'ana']);
        $this->assertFalse($manager->isRefreshDue($session, 300));

        $manager->forgetCheck($session);

        $this->assertTrue($manager->isRefreshDue($session, 300));
    }

    #[Test]
    public function withoutAnIntervalThereIsNothingToAskAgain(): void
    {
        $session = new Session(['user' => ['identity' => 'ana'], 'auth_checked_at' => 1]);

        $this->assertFalse((new SessionManager())->isRefreshDue($session, null));
    }

    #[Test]
    public function theTimeOfTheCheckGoesWithTheUser(): void
    {
        $manager = new SessionManager();
        $session = new Session([]);
        $manager->storeUserInfo($session, ['identity' => 'ana']);

        $manager->clearUserInfo($session);

        $this->assertNull($session->get('auth_checked_at'));
    }

    /** @return iterable<string, array{mixed}> */
    public static function invalidRedirectValues(): iterable
    {
        yield 'array' => [[]];
        yield 'boolean' => [false];
        yield 'integer' => [0];
        yield 'float' => [1.5];
        yield 'object' => [new stdClass()];
        yield 'Stringable' => [new class () implements Stringable {
            public function __toString(): string
            {
                return '/private';
            }
        }];
    }

    #[DataProvider('invalidRedirectValues')]
    public function testRejectsNonStringRedirects(mixed $value): void
    {
        $this->expectException(TranslatableInvalidArgumentException::class);
        $this->expectExceptionMessage('"auth_redirect"');

        (new SessionManager())->getRedirectUrl(new Session(['auth_redirect' => $value]));
    }

    public function testOptionalRedirectsAndTheirExactStringValuesArePreserved(): void
    {
        $manager = new SessionManager();
        $this->assertNull($manager->getRedirectUrl(new Session([])));
        foreach ([null, '', '0', '/private?tab=2', ' https://example.com/ '] as $value) {
            $this->assertSame($value, $manager->getRedirectUrl(new Session(['auth_redirect' => $value])));
        }
    }

    public function testInvalidRedirectRetainsItsFieldAndValueCauseWithoutChangingTheSession(): void
    {
        $session = new Session(['auth_redirect' => ['/private']]);

        try {
            (new SessionManager())->getRedirectUrl($session);
            $this->fail('An array must not be accepted as a redirect URL.');
        } catch (ArrayTypeMismatchException $exception) {
            $this->assertStringContainsString('"auth_redirect"', $exception->getMessage());
            $cause = $exception->getPrevious();
            $this->assertInstanceOf(ValueTypeMismatchException::class, $cause);
            $this->assertSame('auth_redirect', $cause->getTranslatableMessage()->getParameters()['path']);
            $this->assertSame(['/private'], $session->get('auth_redirect'));
        }
    }

    /** @return iterable<string, array{mixed}> */
    public static function invalidCheckTimes(): iterable
    {
        yield 'numeric string' => ['123'];
        yield 'nonnumeric string' => ['yesterday'];
        yield 'boolean' => [false];
        yield 'float' => [123.5];
        yield 'array' => [[]];
        yield 'object' => [new stdClass()];
    }

    #[DataProvider('invalidCheckTimes')]
    public function testRejectsNonIntegerCheckTimesWhenTheIntervalUsesThem(mixed $value): void
    {
        $this->expectException(TranslatableInvalidArgumentException::class);
        $this->expectExceptionMessage('"auth_checked_at"');

        (new SessionManager())->isRefreshDue(new Session(['auth_checked_at' => $value]), 300);
    }

    #[DataProvider('invalidCheckTimes')]
    public function testWithoutAnIntervalAnExistingCheckTimeIsNotUsed(mixed $value): void
    {
        $this->assertFalse((new SessionManager())->isRefreshDue(new Session(['auth_checked_at' => $value]), null));
    }

    public function testNullCheckTimeStillRequiresARefreshWithOrWithoutAnInterval(): void
    {
        $manager = new SessionManager();
        $session = new Session(['auth_checked_at' => null]);

        $this->assertTrue($manager->isRefreshDue($session, 300));
        $this->assertTrue($manager->isRefreshDue($session, null));
    }

    /** @return iterable<string, array{mixed, string}> */
    public static function invalidUserInformation(): iterable
    {
        yield 'string' => ['ana', 'user'];
        yield 'integer' => [1, 'user'];
        yield 'boolean' => [false, 'user'];
        yield 'float' => [1.5, 'user'];
        yield 'object' => [new stdClass(), 'user'];
        yield 'list' => [['ana'], 'key'];
        yield 'numeric key' => [[3 => 'ana'], 'key'];
        yield 'mixed keys' => [['identity' => 'ana', 3 => 'extra'], 'key'];
        yield 'numeric string converted by PHP' => [['123' => 'extra'], 'key'];
    }

    #[DataProvider('invalidUserInformation')]
    public function testRejectsInvalidUserInformation(mixed $value, string $key): void
    {
        $this->expectException(TranslatableInvalidArgumentException::class);
        $this->expectExceptionMessage('"' . $key . '"');

        (new SessionManager())->getUserInfo(new Session(['user' => $value]));
    }

    public function testMissingNullAndEmptyUserInformationKeepTheirMeanings(): void
    {
        $manager = new SessionManager();

        $this->assertNull($manager->getUserInfo(new Session([])));
        $this->assertNull($manager->getUserInfo(new Session(['user' => null])));
        $this->assertSame([], $manager->getUserInfo(new Session(['user' => []])));
    }

    public function testUserInformationKeepsItsValuesOrderAndStringKeys(): void
    {
        $userInfo = [
            'sub' => 'user-1',
            'roles' => ['editor'],
            'details' => [7 => 'numbered detail'],
            'active' => false,
            'optional' => null,
            'object' => new stdClass(),
            '01' => 'string key with a leading zero',
            '' => 'empty string key',
        ];
        $manager = new SessionManager();
        $session = new Session([]);
        $manager->storeUserInfo($session, $userInfo);

        $stored = $session->get('user');

        $this->assertSame($stored, $manager->getUserInfo($session));
    }
}
