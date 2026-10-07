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

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\User;
use Derafu\Auth\UserFactory;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The users: the authenticated one, the anonymous one and the factory that
 * makes them for Mezzio.
 */
#[CoversClass(User::class)]
#[CoversClass(AnonymousUser::class)]
#[CoversClass(UserFactory::class)]
final class UserTest extends TestCase
{
    private function user(): User
    {
        return new User('ana@example.com', ['admin', 'editor'], ['name' => 'Ana', 'age' => 30]);
    }

    #[Test]
    public function aUserHasItsIdentityRolesAndDetails(): void
    {
        $user = $this->user();

        $this->assertSame('ana@example.com', $user->getIdentity());
        $this->assertSame(['admin', 'editor'], $user->getRoles());
        $this->assertSame(['name' => 'Ana', 'age' => 30], $user->getDetails());
        $this->assertFalse($user->isAnonymous());
    }

    #[Test]
    public function aUserWithoutRolesNorDetailsHasNone(): void
    {
        $user = new User('ana@example.com');

        $this->assertSame([], $user->getRoles());
        $this->assertSame([], $user->getDetails());
    }

    #[Test]
    public function aDetailIsReadByNameWithADefault(): void
    {
        $user = $this->user();

        $this->assertSame('Ana', $user->getDetail('name'));
        $this->assertNull($user->getDetail('missing'));
        $this->assertSame('none', $user->getDetail('missing', 'none'));
    }

    #[Test]
    public function aUserHasARoleOrNot(): void
    {
        $user = $this->user();

        $this->assertTrue($user->hasRole('admin'));
        $this->assertFalse($user->hasRole('guest'));
        $this->assertFalse($user->hasRole('Admin'));
    }

    #[Test]
    public function aUserHasAnyOfTheRoles(): void
    {
        $user = $this->user();

        $this->assertTrue($user->hasAnyRole(['guest', 'editor']));
        $this->assertFalse($user->hasAnyRole(['guest', 'owner']));
        $this->assertFalse($user->hasAnyRole([]));
    }

    #[Test]
    public function aUserHasAllOfTheRoles(): void
    {
        $user = $this->user();

        $this->assertTrue($user->hasAllRoles(['admin', 'editor']));
        $this->assertTrue($user->hasAllRoles(['admin']));
        $this->assertFalse($user->hasAllRoles(['admin', 'guest']));
        $this->assertTrue($user->hasAllRoles([]));
    }

    #[Test]
    public function theAnonymousUserIsAnonymousWithTheRoleAnonymous(): void
    {
        $user = new AnonymousUser();

        $this->assertTrue($user->isAnonymous());
        $this->assertSame('anonymous', $user->getIdentity());
        $this->assertSame(['anonymous'], $user->getRoles());
        $this->assertTrue($user->hasRole('anonymous'));
        $this->assertFalse($user->hasRole('admin'));
    }

    #[Test]
    public function theFactoryMakesUsersForMezzio(): void
    {
        $factory = (new UserFactory())();

        $user = $factory('ana@example.com', ['admin'], ['name' => 'Ana']);

        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('ana@example.com', $user->getIdentity());
        $this->assertSame(['admin'], $user->getRoles());
        $this->assertSame('Ana', $user->getDetail('name'));
    }

    #[Test]
    public function theFactoryRequiresTheRolesToBeStrings(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new UserFactory())()('ana@example.com', ['admin', 7]);
    }

    #[Test]
    public function theFactoryRequiresTheDetailsToBeAMap(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new UserFactory())()('ana@example.com', [], ['a list', 'of values']);
    }
}
