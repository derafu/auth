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

use Derafu\Auth\SessionManager;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
}
