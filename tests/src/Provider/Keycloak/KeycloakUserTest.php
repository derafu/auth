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

use Derafu\Auth\Provider\Keycloak\KeycloakUser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Tests for KeycloakUser.
 */
#[CoversClass(KeycloakUser::class)]
class KeycloakUserTest extends TestCase
{
    #[Test]
    public function testUserIdentityExtraction(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'preferred_username' => 'john.doe',
            'email' => 'john.doe@example.com',
        ];

        $user = new KeycloakUser($userInfo);

        $this->assertSame('user-123', $user->getIdentity());
        $this->assertFalse($user->isAnonymous());
    }

    #[Test]
    public function testRoleExtractionFromRealmAccess(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'realm_access' => [
                'roles' => ['user', 'admin', 'editor'],
            ],
        ];

        $user = new KeycloakUser($userInfo);
        $roles = iterator_to_array($user->getRoles());

        $this->assertContains('user', $roles);
        $this->assertContains('admin', $roles);
        $this->assertContains('editor', $roles);
        $this->assertCount(3, $roles);
    }

    #[Test]
    public function testRoleExtractionFromResourceAccess(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'resource_access' => [
                'client-1' => [
                    'roles' => ['client1-role-a', 'client1-role-b'],
                ],
                'client-2' => [
                    'roles' => ['client2-role-a'],
                ],
            ],
        ];

        $user = new KeycloakUser($userInfo, 'client-1');
        $roles = iterator_to_array($user->getRoles());

        // Only the roles of the client of the application: what the user can do
        // in another client says nothing about this one.
        $this->assertContains('client1-role-a', $roles);
        $this->assertContains('client1-role-b', $roles);
        $this->assertNotContains('client2-role-a', $roles);
        $this->assertCount(2, $roles);
    }

    #[Test]
    public function testRolesOfOtherClientsAreNotTheRolesOfTheUser(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'resource_access' => [
                'account' => ['roles' => ['manage-account', 'view-profile']],
                'my-client' => ['roles' => ['viewer']],
            ],
        ];

        $this->assertSame(['viewer'], (new KeycloakUser($userInfo, 'my-client'))->getRoles());
        $this->assertSame([], (new KeycloakUser($userInfo, 'another-client'))->getRoles());
        $this->assertSame([], (new KeycloakUser($userInfo))->getRoles());
    }

    #[Test]
    public function testRoleExtractionFromBothRealmAndResourceAccess(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'realm_access' => [
                'roles' => ['realm-admin', 'realm-user'],
            ],
            'resource_access' => [
                'my-client' => [
                    'roles' => ['client-admin', 'client-viewer'],
                ],
            ],
        ];

        $user = new KeycloakUser($userInfo, 'my-client');
        $roles = iterator_to_array($user->getRoles());

        // Should have all roles from both realm and resource access
        $this->assertContains('realm-admin', $roles);
        $this->assertContains('realm-user', $roles);
        $this->assertContains('client-admin', $roles);
        $this->assertContains('client-viewer', $roles);
        $this->assertCount(4, $roles);
    }

    #[Test]
    public function testRoleExtractionWithDuplicates(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'realm_access' => [
                'roles' => ['admin', 'user', 'admin'], // 'admin' is duplicated
            ],
            'resource_access' => [
                'client-1' => [
                    'roles' => ['admin', 'viewer'], // 'admin' appears again
                ],
            ],
        ];

        $user = new KeycloakUser($userInfo, 'client-1');
        $roles = iterator_to_array($user->getRoles());

        // Should have unique roles only
        $this->assertContains('admin', $roles);
        $this->assertContains('user', $roles);
        $this->assertContains('viewer', $roles);
        $this->assertCount(3, $roles); // No duplicates
    }

    #[Test]
    public function testRoleExtractionWithEmptyAccess(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            // No realm_access or resource_access
        ];

        $user = new KeycloakUser($userInfo);
        $roles = iterator_to_array($user->getRoles());

        $this->assertEmpty($roles);
    }

    #[Test]
    public function testRoleExtractionWithMalformedData(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'realm_access' => 'not-an-array', // Should be array
            'resource_access' => [
                'client-1' => 'not-an-array', // Should be array
                'client-2' => [
                    'roles' => 'not-an-array', // Should be array
                ],
            ],
        ];

        foreach (['client-1', 'client-2'] as $client) {
            $this->assertEmpty(iterator_to_array((new KeycloakUser($userInfo, $client))->getRoles()));
        }
    }

    #[Test]
    public function testDetailExtractionMethods(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'preferred_username' => 'john.doe',
            'email' => 'john.doe@example.com',
            'name' => 'John Doe',
            'given_name' => 'John',
            'family_name' => 'Doe',
            'custom_field' => 'custom_value',
        ];

        $user = new KeycloakUser($userInfo);

        // Test convenience methods
        $this->assertSame('john.doe@example.com', $user->getEmail());
        $this->assertSame('John Doe', $user->getName());
        $this->assertSame('John', $user->getGivenName());
        $this->assertSame('Doe', $user->getFamilyName());

        // Test generic detail access
        $this->assertSame('john.doe', $user->getDetail('preferred_username'));
        $this->assertSame('custom_value', $user->getDetail('custom_field'));
        $this->assertSame('default', $user->getDetail('nonexistent', 'default'));

        // Test getDetails returns all data
        $this->assertSame($userInfo, $user->getDetails());
    }

    #[Test]
    public function testDetailExtractionWithMissingFields(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            // Missing email, name, etc.
        ];

        $user = new KeycloakUser($userInfo);

        $this->assertNull($user->getEmail());
        $this->assertNull($user->getName());
        $this->assertNull($user->getGivenName());
        $this->assertNull($user->getFamilyName());
    }

    #[Test]
    public function testPreferredUsernameExtraction(): void
    {
        // Test that preferred_username is accessible via getDetail
        $userInfo = [
            'sub' => 'user-123',
            'preferred_username' => 'john.doe',
            'email' => 'john@example.com',
        ];

        $user = new KeycloakUser($userInfo);
        $this->assertSame('john.doe', $user->getDetail('preferred_username'));
        $this->assertSame('john@example.com', $user->getEmail());
        $this->assertSame('user-123', $user->getIdentity());
    }
}
