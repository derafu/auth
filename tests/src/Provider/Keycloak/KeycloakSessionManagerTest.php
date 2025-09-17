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
        $this->assertFalse($this->sessionManager->isTokenExpired($session));
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

        // Should not be expired if no expiry time is set
        $this->assertFalse($this->sessionManager->isTokenExpired($session));
    }

    #[Test]
    public function testTokenExpirationCheck(): void
    {
        $session = new Session([]);

        // Store expired token
        $expiredTokenInfo = [
            'access_token' => 'expired-token',
            'expires' => time() - 3600, // 1 hour ago
        ];

        $this->sessionManager->storeAuthInfo($session, $expiredTokenInfo);

        $this->assertTrue($this->sessionManager->isTokenExpired($session));

        // Store valid token
        $validTokenInfo = [
            'access_token' => 'valid-token',
            'expires' => time() + 3600, // 1 hour from now
        ];

        $this->sessionManager->storeAuthInfo($session, $validTokenInfo);

        $this->assertFalse($this->sessionManager->isTokenExpired($session));
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
        $this->assertFalse($this->sessionManager->isTokenExpired($session));
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
        $this->assertFalse($this->sessionManager->isTokenExpired($session));
    }
}
