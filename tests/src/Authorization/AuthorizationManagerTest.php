<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authorization;

use Derafu\Auth\Authorization\AccessRules;
use Derafu\Auth\Authorization\AuthorizationManager;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\User;
use Derafu\Routing\ValueObject\Route;
use Derafu\Routing\ValueObject\RouteMatch;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Who is granted in each path: by the roles of the protected path, by the route
 * that was matched, and by the roles of the user of the request, which is where
 * the authentication middleware of Mezzio puts it (with the name of its interface).
 */
#[CoversClass(AuthorizationManager::class)]
#[UsesClass(AccessRules::class)]
#[UsesClass(User::class)]
final class AuthorizationManagerTest extends TestCase
{
    private function authorization(): AuthorizationManager
    {
        return new AuthorizationManager(new AccessRules([
            'protected_paths' => ['/private', '/admin' => 'admin', '/staff' => ['editor', 'admin']],
        ]));
    }

    /**
     * @param array<string> $roles
     */
    private function route(array $roles): RouteMatch
    {
        return new RouteMatch(new Route('page', '/page', 'PageController@index', [], [], $roles));
    }

    private function request(string $path, ?UserInterface $user = null): ServerRequestInterface
    {
        $request = (new ServerRequest())->withUri(new Uri('https://app.test' . $path));

        return $user === null ? $request : $request->withAttribute(MezzioUserInterface::class, $user);
    }

    #[Test]
    public function nothingIsRequiredInAPathThatIsNotProtectedAndWhoseRouteHasNoRoles(): void
    {
        $authorization = $this->authorization();

        $this->assertTrue($authorization->isGranted('anonymous', $this->request('/public')));
        $this->assertTrue($authorization->isGranted('any', $this->request('/public')->withAttribute('derafu.route', $this->route([]))));
    }

    #[Test]
    public function theRolesOfAProtectedPathAreTheOnesThatAreGranted(): void
    {
        $authorization = $this->authorization();

        $this->assertTrue($authorization->isGranted('admin', $this->request('/admin/users')));
        $this->assertFalse($authorization->isGranted('editor', $this->request('/admin/users')));
        $this->assertTrue($authorization->isGranted('editor', $this->request('/staff')));
        $this->assertTrue($authorization->isGranted('admin', $this->request('/staff')));
        $this->assertFalse($authorization->isGranted('guest', $this->request('/staff')));
    }

    #[Test]
    public function aProtectedPathWithoutRolesAndWithoutRouteIsGranted(): void
    {
        $this->assertTrue($this->authorization()->isGranted('guest', $this->request('/private/page')));
    }

    #[Test]
    public function aProtectedPathWithoutRolesRequiresTheRolesOfTheRouteThatWasMatched(): void
    {
        $request = $this->request('/private/page')->withAttribute('derafu.route', $this->route(['editor']));
        $authorization = $this->authorization();

        $this->assertTrue($authorization->isGranted('editor', $request));
        $this->assertFalse($authorization->isGranted('guest', $request));
    }

    #[Test]
    public function aProtectedPathWithoutRolesIsGrantedWhenTheRouteHasNoRolesEither(): void
    {
        $request = $this->request('/private/page')->withAttribute('derafu.route', $this->route([]));

        $this->assertTrue($this->authorization()->isGranted('guest', $request));
    }

    #[Test]
    public function theRolesOfARouteAreRequiredEvenWhenItsPathIsNotProtected(): void
    {
        $request = $this->request('/open')->withAttribute('derafu.route', $this->route(['admin']));
        $authorization = $this->authorization();

        $this->assertTrue($authorization->isGranted('admin', $request));
        $this->assertFalse($authorization->isGranted('editor', $request));
    }

    #[Test]
    public function theRolesOfTheProtectedPathCountMoreThanTheRoute(): void
    {
        $request = $this->request('/admin/users')->withAttribute('derafu.route', $this->route(['editor']));
        $authorization = $this->authorization();

        $this->assertFalse($authorization->isGranted('editor', $request));
        $this->assertTrue($authorization->isGranted('admin', $request));
    }

    #[Test]
    public function aValueThatIsNotARouteMatchIsNotARoute(): void
    {
        $route = new class () {
            public function getRoles(): array
            {
                return ['admin'];
            }
        };
        $request = $this->request('/open')->withAttribute('derafu.route', $route);

        $this->assertSame([], AccessRules::routeRoles($request));
        $this->assertTrue($this->authorization()->isGranted('guest', $request));
    }

    #[Test]
    public function theRolesOfTheRouteAreThoseOfTheMatchOrNoneWithoutIt(): void
    {
        $this->assertSame(['admin'], AccessRules::routeRoles(
            $this->request('/open')->withAttribute('derafu.route', $this->route(['admin']))
        ));
        $this->assertSame([], AccessRules::routeRoles($this->request('/open')));
    }

    #[Test]
    public function anyOfTheRolesIsEnoughForTheUserOfTheRequest(): void
    {
        $authorization = $this->authorization();
        $user = new User('ana@example.com', ['editor']);

        $this->assertTrue($authorization->isGrantedAny(['admin', 'editor'], $this->request('/private', $user)));
        $this->assertFalse($authorization->isGrantedAny(['admin', 'owner'], $this->request('/private', $user)));
    }

    #[Test]
    public function noRolesRequiredGrantsNothingToAny(): void
    {
        $user = new User('ana@example.com', ['editor']);

        $this->assertFalse($this->authorization()->isGrantedAny([], $this->request('/private', $user)));
    }

    #[Test]
    public function withoutUserNothingIsGrantedWhenRolesAreRequired(): void
    {
        $authorization = $this->authorization();
        $request = $this->request('/private');

        $this->assertFalse($authorization->isGrantedAny(['admin'], $request));
        $this->assertFalse($authorization->isGrantedAll(['admin'], $request));
    }

    #[Test]
    public function aValueThatIsNotAUserIsNoUser(): void
    {
        $request = $this->request('/private')->withAttribute(MezzioUserInterface::class, 'ana');

        $this->assertFalse($this->authorization()->isGrantedAny(['admin'], $request));
    }

    #[Test]
    public function allTheRolesAreNeededForTheUserOfTheRequest(): void
    {
        $authorization = $this->authorization();
        $user = new User('ana@example.com', ['editor', 'admin']);

        $this->assertTrue($authorization->isGrantedAll(['admin', 'editor'], $this->request('/private', $user)));
        $this->assertFalse($authorization->isGrantedAll(['admin', 'owner'], $this->request('/private', $user)));
    }

    #[Test]
    public function noRolesRequiredIsGrantedToAllOnlyToAUser(): void
    {
        $authorization = $this->authorization();

        // All of no roles is for a user, not for nobody.
        $this->assertTrue($authorization->isGrantedAll([], $this->request('/private', new User('ana@example.com'))));
        $this->assertFalse($authorization->isGrantedAll([], $this->request('/private')));
    }

    #[Test]
    public function withoutUserNoRolesRequiredIsNotGrantedToAnyEither(): void
    {
        $this->assertFalse($this->authorization()->isGrantedAny([], $this->request('/private')));
    }

    #[Test]
    public function theUserOfTheRequestIsWhatCountsEvenInAPathThatIsNotProtected(): void
    {
        $authorization = $this->authorization();
        $user = new User('ana@example.com', ['editor']);

        $this->assertFalse($authorization->isGrantedAny(['admin'], $this->request('/public')));
        $this->assertFalse($authorization->isGrantedAll([], $this->request('/public')));
        $this->assertTrue($authorization->isGrantedAny(['editor'], $this->request('/public', $user)));
        $this->assertTrue($authorization->isGrantedAll(['editor'], $this->request('/public', $user)));
        $this->assertFalse($authorization->isGrantedAny(['admin'], $this->request('/public', $user)));
    }
}
