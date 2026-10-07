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
use PHPUnit\Framework\Attributes\DataProvider;
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

    #[Test]
    public function theStandardFieldsAreReadFromTheDetails(): void
    {
        $user = new User('sub-1', [], [
            'name' => 'Ana Perez',
            'given_name' => 'Ana',
            'family_name' => 'Perez',
            'email' => 'ana@example.com',
            'email_verified' => true,
            'preferred_username' => 'ana',
            'locale' => 'es',
        ]);

        $this->assertSame('Ana Perez', $user->getName());
        $this->assertSame('Ana', $user->getGivenName());
        $this->assertSame('Perez', $user->getFamilyName());
        $this->assertSame('ana@example.com', $user->getEmail());
        $this->assertTrue($user->isEmailVerified());
        $this->assertSame('ana', $user->getUsername());
        $this->assertSame('es', $user->getLocale());
    }

    #[Test]
    public function aFieldThatIsNotThereIsNullAndNothingFails(): void
    {
        // A user that has none of them: a table without those columns, a realm
        // user without names or email.
        $user = new User('sub-1', ['admin'], ['id' => 7]);

        $this->assertNull($user->getName());
        $this->assertNull($user->getGivenName());
        $this->assertNull($user->getFamilyName());
        $this->assertNull($user->getEmail());
        $this->assertFalse($user->isEmailVerified());
        $this->assertNull($user->getUsername());
        $this->assertNull($user->getLocale());

        // Neither does the user that has no details at all.
        $this->assertNull((new User('sub-2'))->getEmail());
        $this->assertNull((new AnonymousUser())->getName());
    }

    #[Test]
    public function theNameFallsBackToTheUsernameAndTheUsernameToTheEmail(): void
    {
        $this->assertSame('ana', (new User('s', [], ['preferred_username' => 'ana']))->getName());
        $this->assertSame('Ana Perez', (new User('s', [], ['name' => 'Ana Perez', 'preferred_username' => 'ana']))->getName());

        $this->assertSame('ana@example.com', (new User('s', [], ['email' => 'ana@example.com']))->getUsername());
        $this->assertSame('ana', (new User('s', [], ['preferred_username' => 'ana', 'email' => 'ana@example.com']))->getUsername());

        // The email is not the name: the name does not fall back to it.
        $this->assertNull((new User('s', [], ['email' => 'ana@example.com']))->getName());
    }

    #[Test]
    public function anEmptyTextIsNotAValueSoTheFallbacksWork(): void
    {
        $user = new User('s', [], ['name' => '', 'preferred_username' => 'ana', 'given_name' => '  ', 'email' => '']);

        $this->assertSame('ana', $user->getName());
        $this->assertNull($user->getGivenName());
        $this->assertNull($user->getEmail());
    }

    /**
     * @return array<string, array{mixed, string|null}>
     */
    public static function valuesOfTheTextFieldsProvider(): array
    {
        return [
            'a text' => ['Ana', 'Ana'],
            'a number' => [123, '123'],
            'a decimal' => [1.5, '1.5'],
            'a boolean' => [true, null],
            'a list' => [['Ana'], null],
            'null' => [null, null],
        ];
    }

    #[Test]
    #[DataProvider('valuesOfTheTextFieldsProvider')]
    public function theTextFieldsAreTextOrNull(mixed $value, ?string $expected): void
    {
        $user = new User('s', [], ['name' => $value, 'given_name' => $value, 'locale' => $value]);

        $this->assertSame($expected, $user->getName());
        $this->assertSame($expected, $user->getGivenName());
        $this->assertSame($expected, $user->getLocale());
    }

    /**
     * @return array<string, array{mixed, bool}>
     */
    public static function valuesOfEmailVerifiedProvider(): array
    {
        return [
            'true' => [true, true],
            'one' => [1, true],
            'the text one' => ['1', true],
            'the text true' => ['true', true],
            'false' => [false, false],
            'zero' => [0, false],
            'the text zero' => ['0', false],
            'the text false' => ['false', false],
            'an empty text' => ['', false],
            'null' => [null, false],
            'a list' => [[true], false],
        ];
    }

    #[Test]
    #[DataProvider('valuesOfEmailVerifiedProvider')]
    public function theEmailIsVerifiedOnlyWhenTheValueSaysYes(mixed $value, bool $expected): void
    {
        $this->assertSame($expected, (new User('s', [], ['email_verified' => $value]))->isEmailVerified());
    }
}
