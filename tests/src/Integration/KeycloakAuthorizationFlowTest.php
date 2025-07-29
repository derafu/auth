<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Integration;

use Derafu\Auth\Adapter\KeycloakAuthorizationAdapter;
use Derafu\Auth\User\KeycloakUser;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use Mezzio\Authentication\UserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeycloakAuthorizationAdapter::class)]
#[CoversClass(KeycloakUser::class)]
class KeycloakAuthorizationFlowTest extends TestCase
{
    private KeycloakAuthorizationAdapter $adapter;

    protected function setUp(): void
    {
        $this->adapter = new KeycloakAuthorizationAdapter();
    }

    #[Test]
    public function testUserWithAdminRoleCanAccessAdminArea(): void
    {
        $user = $this->createUserWithRoles(['admin', 'user']);
        $request = $this->createRequestWithUser($user);

        $this->assertTrue($this->adapter->isGranted('admin', $request));
        $this->assertTrue($this->adapter->isGranted('user', $request));
        $this->assertFalse($this->adapter->isGranted('super_admin', $request));
    }

    #[Test]
    public function testUserWithMultipleRolesCanAccessAnyRole(): void
    {
        $user = $this->createUserWithRoles(['moderator', 'editor', 'viewer']);
        $request = $this->createRequestWithUser($user);

        // Test isGrantedAny - should return true if user has ANY of the roles.
        $this->assertTrue($this->adapter->isGrantedAny(['admin', 'moderator'], $request));
        $this->assertTrue($this->adapter->isGrantedAny(['editor', 'viewer'], $request));
        $this->assertFalse($this->adapter->isGrantedAny(['admin', 'super_admin'], $request));
    }

    #[Test]
    public function testUserWithMultipleRolesCanAccessAllRoles(): void
    {
        $user = $this->createUserWithRoles(['admin', 'moderator', 'editor']);
        $request = $this->createRequestWithUser($user);

        // Test isGrantedAll - should return true if user has ALL of the roles.
        $this->assertTrue($this->adapter->isGrantedAll(['admin', 'moderator'], $request));
        $this->assertTrue($this->adapter->isGrantedAll(['admin', 'moderator', 'editor'], $request));
        $this->assertFalse($this->adapter->isGrantedAll(['admin', 'super_admin'], $request));
    }

    #[Test]
    public function testUserWithoutRolesCannotAccessProtectedAreas(): void
    {
        $user = $this->createUserWithRoles([]);
        $request = $this->createRequestWithUser($user);

        $this->assertFalse($this->adapter->isGranted('admin', $request));
        $this->assertFalse($this->adapter->isGranted('user', $request));
        $this->assertFalse($this->adapter->isGrantedAny(['admin', 'user'], $request));
        $this->assertFalse($this->adapter->isGrantedAll(['admin', 'user'], $request));
    }

    #[Test]
    public function testUserWithResourceSpecificRoles(): void
    {
        $user = $this->createUserWithResourceRoles([
            'app-client' => ['read', 'write'],
            'api-client' => ['read'],
        ]);
        $request = $this->createRequestWithUser($user);

        // Check that roles are properly extracted.
        $userRoles = iterator_to_array($user->getRoles());
        $this->assertContains('read', $userRoles);
        $this->assertContains('write', $userRoles);
        $this->assertNotContains('delete', $userRoles);

        // Test resource-specific roles.
        $this->assertTrue($this->adapter->isGranted('read', $request));
        $this->assertTrue($this->adapter->isGranted('write', $request));
        $this->assertFalse($this->adapter->isGranted('delete', $request));
    }

    #[Test]
    public function testComplexRoleScenarios(): void
    {
        $user = $this->createUserWithRoles(['admin', 'moderator']);
        $request = $this->createRequestWithUser($user);

        // Complex authorization scenarios.
        $this->assertTrue($this->adapter->isGrantedAny(['admin', 'super_admin'], $request));
        $this->assertTrue($this->adapter->isGrantedAll(['admin'], $request));
        $this->assertFalse($this->adapter->isGrantedAll(['admin', 'super_admin'], $request));
    }

    #[Test]
    public function testAuthorizationWithNullUser(): void
    {
        $request = new ServerRequest();
        $request = $request->withUri(new Uri('http://localhost/admin'));

        // Should return false for all authorization checks when no user.
        $this->assertFalse($this->adapter->isGranted('admin', $request));
        $this->assertFalse($this->adapter->isGrantedAny(['admin', 'user'], $request));
        $this->assertFalse($this->adapter->isGrantedAll(['admin', 'user'], $request));
    }

    #[Test]
    public function testAuthorizationWithEmptyRoles(): void
    {
        $user = $this->createUserWithRoles([]);
        $request = $this->createRequestWithUser($user);

        // Empty roles should result in no access.
        $this->assertFalse($this->adapter->isGranted('any-role', $request));
        $this->assertFalse($this->adapter->isGrantedAny(['role1', 'role2'], $request));
        $this->assertFalse($this->adapter->isGrantedAll(['role1', 'role2'], $request));
    }

    #[Test]
    public function testAuthorizationWithCaseSensitiveRoles(): void
    {
        $user = $this->createUserWithRoles(['Admin', 'User']);
        $request = $this->createRequestWithUser($user);

        // Role matching should be case-sensitive.
        $this->assertTrue($this->adapter->isGranted('Admin', $request));
        $this->assertFalse($this->adapter->isGranted('admin', $request));
        $this->assertTrue($this->adapter->isGranted('User', $request));
        $this->assertFalse($this->adapter->isGranted('user', $request));
    }

    private function createUserWithRoles(array $roles): UserInterface
    {
        $userInfo = [
            'sub' => 'user-123',
            'email' => 'test@example.com',
            'name' => 'Test User',
            'realm_access' => [
                'roles' => $roles,
            ],
            'resource_access' => [],
        ];

        return new KeycloakUser($userInfo);
    }

    private function createUserWithResourceRoles(array $resourceRoles): UserInterface
    {
        // Convert resource roles to the expected Keycloak format.
        $formattedResourceAccess = [];
        foreach ($resourceRoles as $resource => $roles) {
            $formattedResourceAccess[$resource] = ['roles' => $roles];
        }

        $userInfo = [
            'sub' => 'user-123',
            'email' => 'test@example.com',
            'name' => 'Test User',
            'realm_access' => [
                'roles' => [],
            ],
            'resource_access' => $formattedResourceAccess,
        ];

        return new KeycloakUser($userInfo);
    }

    private function createRequestWithUser(UserInterface $user): ServerRequest
    {
        $request = new ServerRequest();
        $request = $request->withUri(new Uri('http://localhost/admin'));
        $request = $request->withAttribute(UserInterface::class, $user);

        return $request;
    }
}
