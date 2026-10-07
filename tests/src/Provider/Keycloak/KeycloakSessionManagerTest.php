<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Tests\Provider\Keycloak;

use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Provider\Keycloak\KeycloakSessionManager;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Tests for KeycloakSessionManager.
 */
#[CoversClass(KeycloakSessionManager::class)]
class KeycloakSessionManagerTest extends TestCase
{
    private KeycloakSessionManager $sessionManager;

    protected function setUp(): void
    {
        $this->sessionManager = new KeycloakSessionManager();
    }

    #[Test]
    public function testAuthInfoStorageAndRetrieval(): void
    {
        $session = new Session([]);

        $tokenInfo = [
            'access_token' => 'access-token-123',
            'refresh_token' => 'refresh-token-456',
            'expires' => time() + 3600,
        ];

        // Store auth info
        $this->sessionManager->storeAuthInfo($session, $tokenInfo);

        // Verify storage
        $this->assertTrue($this->sessionManager->hasAuthInfo($session));
        $this->assertSame('refresh-token-456', $this->sessionManager->getRefreshToken($session));
        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);
        $this->assertFalse($this->sessionManager->isRefreshDue($session, null));
    }

    #[Test]
    public function testAuthInfoWithPartialData(): void
    {
        $session = new Session([]);

        // Token info without refresh token or expiry
        $tokenInfo = [
            'access_token' => 'access-token-only',
        ];

        $this->sessionManager->storeAuthInfo($session, $tokenInfo);

        $this->assertTrue($this->sessionManager->hasAuthInfo($session));
        $this->assertNull($this->sessionManager->getRefreshToken($session));

        // Without an expiry the token never tells when to ask again, so the
        // default interval does (it used to be never).
        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);
        $this->assertFalse($this->sessionManager->isRefreshDue($session, null));
        $session->set('auth_checked_at', time() - ConfigurationInterface::DEFAULT_REFRESH_INTERVAL - 1);
        $this->assertTrue($this->sessionManager->isRefreshDue($session, null));
    }

    #[Test]
    public function aTokenThatExpiredIsDueAndOneThatDidNotIsNot(): void
    {
        $session = new Session([]);

        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'expired', 'expires' => time() - 3600]);
        $this->assertTrue($this->sessionManager->isRefreshDue($session, null));

        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'valid', 'expires' => time() + 3600]);
        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);
        $this->assertFalse($this->sessionManager->isRefreshDue($session, null));
    }

    #[Test]
    public function theIntervalAsksAgainBeforeTheTokenExpires(): void
    {
        $session = new Session([]);
        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'valid', 'expires' => time() + 3600]);
        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);

        // Checked 30 seconds ago, every 60: not yet. Checked 61 ago: due, and the
        // token has 59 minutes left.
        $session->set('auth_checked_at', time() - 30);
        $this->assertFalse($this->sessionManager->isRefreshDue($session, 60));
        $session->set('auth_checked_at', time() - 61);
        $this->assertTrue($this->sessionManager->isRefreshDue($session, 60));
    }

    #[Test]
    public function theTokenAsksAgainBeforeTheIntervalWhenItExpiresFirst(): void
    {
        $session = new Session([]);
        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'expired', 'expires' => time() - 1]);
        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);

        // The interval says one hour and it was checked just now: what happens
        // first is the expiration.
        $this->assertTrue($this->sessionManager->isRefreshDue($session, 3600));
    }

    #[Test]
    public function withoutAnExpiryTheIntervalOrTheDefaultDecides(): void
    {
        $session = new Session([]);
        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'no-expiry']);
        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);

        $session->set('auth_checked_at', time() - 61);
        $this->assertTrue($this->sessionManager->isRefreshDue($session, 60));
        $this->assertFalse($this->sessionManager->isRefreshDue($session, null), 'The default is 5 minutes.');
        $session->set('auth_checked_at', time() - 301);
        $this->assertTrue($this->sessionManager->isRefreshDue($session, null));
    }

    #[Test]
    public function aSessionWithoutTheTimeOfTheLastCheckIsDue(): void
    {
        // A session that was made before the time of the check was kept: it is
        // asked once, and from then on it has the time.
        $session = new Session([
            'oauth2_token' => 'token',
            'oauth2_refresh_token' => 'refresh',
            'oauth2_expiry' => time() + 3600,
            'user' => ['sub' => 'user-1'],
        ]);

        $this->assertTrue($this->sessionManager->isRefreshDue($session, 60));
        $this->assertTrue($this->sessionManager->isRefreshDue($session, null));
    }

    #[Test]
    public function aSessionThatForgetsTheCheckIsAskedAgainWhateverTheTokenAndTheIntervalSay(): void
    {
        $session = new Session([]);
        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'valid', 'expires' => time() + 3600]);
        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);
        $this->assertFalse($this->sessionManager->isRefreshDue($session, 600));

        $this->sessionManager->forgetCheck($session);

        $this->assertTrue($this->sessionManager->isRefreshDue($session, 600));
        $this->assertTrue($this->sessionManager->isRefreshDue($session, null));
    }

    #[Test]
    public function theTokenIsExpiredOnlyWhenItHasAnExpiryInThePast(): void
    {
        $session = new Session([]);
        $this->assertFalse($this->sessionManager->isTokenExpired($session));

        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'no-expiry']);
        $this->assertFalse($this->sessionManager->isTokenExpired($session));

        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'expired', 'expires' => time() - 1]);
        $this->assertTrue($this->sessionManager->isTokenExpired($session));

        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'valid', 'expires' => time() + 60]);
        $this->assertFalse($this->sessionManager->isTokenExpired($session));
    }

    #[Test]
    public function aRefreshWithoutAnExpiryDoesNotKeepTheOldOne(): void
    {
        // The expiry of the first token is in the past. The response to the refresh
        // has no expiry: the old one must not stay, or every request would ask
        // again.
        $session = new Session([]);
        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'first', 'expires' => time() - 10]);
        $this->assertTrue($this->sessionManager->isRefreshDue($session, null));

        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'second']);
        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);

        $this->assertNull($session->get('oauth2_expiry'));
        $this->assertFalse($this->sessionManager->isRefreshDue($session, null));
    }

    #[Test]
    public function theTimeOfTheCheckIsKeptWithTheUserAndRemovedWithTheSession(): void
    {
        $session = new Session([]);

        $this->sessionManager->storeUserInfo($session, ['sub' => 'user-1']);
        $this->assertEqualsWithDelta(time(), $session->get('auth_checked_at'), 2);

        $this->sessionManager->clearSession($session);
        $this->assertNull($session->get('auth_checked_at'));
    }

    #[Test]
    public function testUserInfoStorageAndRetrieval(): void
    {
        $session = new Session([]);

        $userInfo = [
            'sub' => 'user-123',
            'email' => 'test@example.com',
            'name' => 'Test User',
            'roles' => ['user', 'admin'],
        ];

        $this->sessionManager->storeUserInfo($session, $userInfo);

        $retrievedUserInfo = $this->sessionManager->getUserInfo($session);

        $this->assertSame($userInfo, $retrievedUserInfo);
        $this->assertSame('user-123', $retrievedUserInfo['sub']);
        $this->assertSame('test@example.com', $retrievedUserInfo['email']);
    }

    #[Test]
    public function testStateManagement(): void
    {
        $session = new Session([]);

        $state = 'random-state-string-123';

        $this->sessionManager->storeState($session, $state);

        $this->assertSame($state, $this->sessionManager->getState($session));

        // Clear state
        $this->sessionManager->clearState($session);

        $this->assertNull($this->sessionManager->getState($session));
    }

    #[Test]
    public function testLoginInProgressManagement(): void
    {
        $session = new Session([]);

        $this->sessionManager->storeState($session, 'state-1');
        $this->sessionManager->storeLogin($session, 'nonce-1', 'pkce-code-1');

        $this->assertSame('nonce-1', $this->sessionManager->getNonce($session));
        $this->assertSame('pkce-code-1', $this->sessionManager->getPkceCode($session));

        // The state, the nonce and the PKCE code are of the login that is in
        // progress: they go together.
        $this->sessionManager->clearState($session);

        $this->assertNull($this->sessionManager->getState($session));
        $this->assertNull($this->sessionManager->getNonce($session));
        $this->assertNull($this->sessionManager->getPkceCode($session));
    }

    #[Test]
    public function testIdTokenIsStoredWithTheAuthInfoAndCleared(): void
    {
        $session = new Session([]);

        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'token', 'id_token' => 'id-token']);
        $this->assertSame('id-token', $this->sessionManager->getIdToken($session));

        // A token response without an ID token does not remove the one that is.
        $this->sessionManager->storeAuthInfo($session, ['access_token' => 'token-2']);
        $this->assertSame('id-token', $this->sessionManager->getIdToken($session));

        $this->sessionManager->clearSession($session);
        $this->assertNull($this->sessionManager->getIdToken($session));
    }

    #[Test]
    public function testRedirectUrlManagement(): void
    {
        $session = new Session([]);

        $redirectUrl = 'https://app.example.com/dashboard';

        $this->sessionManager->storeRedirectUrl($session, $redirectUrl);

        $this->assertSame($redirectUrl, $this->sessionManager->getRedirectUrl($session));
    }

    #[Test]
    public function testSessionClearRemovesAllData(): void
    {
        $session = new Session([]);

        // Store various data
        $this->sessionManager->storeAuthInfo($session, [
            'access_token' => 'token',
            'refresh_token' => 'refresh',
            'expires' => time() + 3600,
        ]);

        $this->sessionManager->storeUserInfo($session, [
            'sub' => 'user-123',
            'email' => 'test@example.com',
        ]);

        $this->sessionManager->storeState($session, 'state-123');
        $this->sessionManager->storeRedirectUrl($session, 'https://example.com');

        // Verify data exists
        $this->assertTrue($this->sessionManager->hasAuthInfo($session));
        $this->assertNotNull($this->sessionManager->getUserInfo($session));
        $this->assertNotNull($this->sessionManager->getState($session));
        $this->assertNotNull($this->sessionManager->getRedirectUrl($session));

        // Clear session
        $this->sessionManager->clearSession($session);

        // Verify all data is cleared
        $this->assertFalse($this->sessionManager->hasAuthInfo($session));
        $this->assertNull($this->sessionManager->getUserInfo($session));
        $this->assertNull($this->sessionManager->getState($session));
        $this->assertNull($this->sessionManager->getRefreshToken($session));
        $this->assertNull($this->sessionManager->getRedirectUrl($session));
    }

    #[Test]
    public function testGettersWithEmptySession(): void
    {
        $session = new Session([]);

        // All getters should return null or false for empty session
        $this->assertFalse($this->sessionManager->hasAuthInfo($session));
        $this->assertNull($this->sessionManager->getRefreshToken($session));
        $this->assertNull($this->sessionManager->getUserInfo($session));
        $this->assertNull($this->sessionManager->getState($session));
        $this->assertNull($this->sessionManager->getRedirectUrl($session));
    }

    #[Test]
    public function testCompleteAuthenticationFlow(): void
    {
        $session = new Session([]);

        // 1. Store state for CSRF protection
        $state = 'csrf-state-456';
        $this->sessionManager->storeState($session, $state);

        // 2. Store redirect URL
        $redirectUrl = 'https://app.example.com/protected';
        $this->sessionManager->storeRedirectUrl($session, $redirectUrl);

        // 3. After successful OAuth callback, store tokens and user info
        $tokenInfo = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires' => time() + 3600,
        ];

        $userInfo = [
            'sub' => 'authenticated-user',
            'email' => 'user@example.com',
            'name' => 'Authenticated User',
        ];

        $this->sessionManager->storeAuthInfo($session, $tokenInfo);
        $this->sessionManager->storeUserInfo($session, $userInfo);

        // 4. Clear state after successful authentication
        $this->sessionManager->clearState($session);

        // Verify final state
        $this->assertTrue($this->sessionManager->hasAuthInfo($session));
        $this->assertSame($userInfo, $this->sessionManager->getUserInfo($session));
        $this->assertSame($redirectUrl, $this->sessionManager->getRedirectUrl($session));
        $this->assertNull($this->sessionManager->getState($session)); // Should be cleared
        $this->assertFalse($this->sessionManager->isRefreshDue($session, null));
    }
}
