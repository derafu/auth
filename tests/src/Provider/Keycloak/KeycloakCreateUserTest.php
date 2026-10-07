<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Keycloak;

use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\User;
use Derafu\Auth\UserFactory;
use Derafu\TestsAuth\Fixture\CustomUser;
use Derafu\TestsAuth\Fixture\CustomUserFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The user that the provider makes from what Keycloak says (the claims of the
 * tokens and the user info): its identity is the `sub`, its roles are the ones of
 * the realm and the ones of the client of the application, and the claims are
 * its details. What is not there is null, and nothing fails.
 */
#[CoversClass(KeycloakUserRepository::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(User::class)]
#[UsesClass(UserFactory::class)]
final class KeycloakCreateUserTest extends TestCase
{
    private function repository(?string $clientId = 'my-client', ?CustomUserFactory $factory = null): KeycloakUserRepository
    {
        return new KeycloakUserRepository(
            new KeycloakConfiguration([
                'keycloak_url' => 'https://auth.example.com',
                'realm' => 'test',
                'client_id' => $clientId ?? '',
                'client_secret' => 'secret',
                'redirect_uri' => 'https://app.example.com/auth/callback',
            ]),
            userFactory: $factory
        );
    }

    #[Test]
    public function theIdentityIsTheSubAndTheClaimsAreTheDetails(): void
    {
        $claims = [
            'sub' => 'user-123',
            'preferred_username' => 'john.doe',
            'email' => 'john.doe@example.com',
            'custom_field' => 'custom_value',
        ];

        $user = $this->repository()->createUser($claims);

        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('user-123', $user->getIdentity());
        $this->assertFalse($user->isAnonymous());
        $this->assertSame($claims, $user->getDetails());
        $this->assertSame('custom_value', $user->getDetail('custom_field'));
        $this->assertSame('default', $user->getDetail('nonexistent', 'default'));
    }

    #[Test]
    public function aUserWithoutSubIsRejected(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('User identity not found in keycloak user info.');

        $this->repository()->createUser(['email' => 'john@example.com']);
    }

    #[Test]
    public function theStandardFieldsAreTheClaimsOfOpenIdConnect(): void
    {
        $user = $this->repository()->createUser([
            'sub' => 'user-123',
            'name' => 'John Doe',
            'given_name' => 'John',
            'family_name' => 'Doe',
            'email' => 'john.doe@example.com',
            'email_verified' => true,
            'preferred_username' => 'john.doe',
            'locale' => 'en',
        ]);

        $this->assertSame('John Doe', $user->getName());
        $this->assertSame('John', $user->getGivenName());
        $this->assertSame('Doe', $user->getFamilyName());
        $this->assertSame('john.doe@example.com', $user->getEmail());
        $this->assertTrue($user->isEmailVerified());
        $this->assertSame('john.doe', $user->getUsername());
        $this->assertSame('en', $user->getLocale());
    }

    #[Test]
    public function aUserWithoutNamesNorEmailHasNullAndNothingFails(): void
    {
        // What a user that was created with only a username is.
        $user = $this->repository()->createUser(['sub' => 'user-123', 'preferred_username' => 'ben']);

        $this->assertNull($user->getGivenName());
        $this->assertNull($user->getFamilyName());
        $this->assertNull($user->getEmail());
        $this->assertFalse($user->isEmailVerified());
        $this->assertNull($user->getLocale());
        // The name and the username have the fallbacks.
        $this->assertSame('ben', $user->getName());
        $this->assertSame('ben', $user->getUsername());
    }

    #[Test]
    public function theRolesAreTheOnesOfTheRealmAndOfTheClientOfTheApplication(): void
    {
        $claims = [
            'sub' => 'user-123',
            'realm_access' => ['roles' => ['realm-admin', 'realm-user']],
            'resource_access' => [
                'my-client' => ['roles' => ['client-admin', 'client-viewer']],
                'account' => ['roles' => ['manage-account', 'view-profile']],
            ],
        ];

        $roles = iterator_to_array($this->repository('my-client')->createUser($claims)->getRoles());

        // Not the ones that the user has in another client: they say nothing
        // about this application.
        $this->assertEqualsCanonicalizing(['realm-admin', 'realm-user', 'client-admin', 'client-viewer'], $roles);
    }

    #[Test]
    public function aClientThatIsNotTheOneOfTheApplicationHasNoRolesHere(): void
    {
        $claims = ['sub' => 'u', 'resource_access' => ['my-client' => ['roles' => ['viewer']]]];

        $this->assertSame(['viewer'], $this->repository('my-client')->createUser($claims)->getRoles());
        $this->assertSame([], $this->repository('another-client')->createUser($claims)->getRoles());
        $this->assertSame([], $this->repository(null)->createUser($claims)->getRoles());
    }

    #[Test]
    public function theRolesHaveNoDuplicatesAndAUserWithoutRolesHasNone(): void
    {
        $claims = [
            'sub' => 'u',
            'realm_access' => ['roles' => ['admin', 'user', 'admin']],
            'resource_access' => ['my-client' => ['roles' => ['admin', 'viewer']]],
        ];

        $this->assertEqualsCanonicalizing(
            ['admin', 'user', 'viewer'],
            iterator_to_array($this->repository()->createUser($claims)->getRoles())
        );
        $this->assertSame([], $this->repository()->createUser(['sub' => 'u'])->getRoles());
    }

    #[Test]
    public function malformedAccessClaimsGiveNoRolesAndDoNotFail(): void
    {
        $claims = [
            'sub' => 'u',
            'realm_access' => 'not-an-array',
            'resource_access' => [
                'my-client' => 'not-an-array',
                'other' => ['roles' => 'not-an-array'],
            ],
        ];

        $this->assertSame([], $this->repository('my-client')->createUser($claims)->getRoles());
        $this->assertSame([], $this->repository('other')->createUser($claims)->getRoles());
    }

    #[Test]
    public function aRoleThatIsNotATextIsNotARole(): void
    {
        $claims = ['sub' => 'u', 'realm_access' => ['roles' => ['admin', 7, null, ['x'], 'editor']]];

        $this->assertSame(['admin', 'editor'], $this->repository()->createUser($claims)->getRoles());
    }

    #[Test]
    public function theFactoryOfTheApplicationMakesTheUser(): void
    {
        $user = $this->repository(factory: new CustomUserFactory())->createUser([
            'sub' => 'user-123',
            'rut' => '11111111-1',
            'realm_access' => ['roles' => ['admin']],
        ]);

        $this->assertInstanceOf(CustomUser::class, $user);
        $this->assertSame('11111111-1', $user->getRut());
        $this->assertSame('user-123', $user->getIdentity());
        $this->assertSame(['admin'], $user->getRoles());
    }
}
