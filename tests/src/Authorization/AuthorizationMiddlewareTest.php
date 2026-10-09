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
use Derafu\Auth\UnauthorizedResponseFactory;
use Derafu\Auth\User;
use Derafu\Routing\ValueObject\Route;
use Derafu\Routing\ValueObject\RouteMatch;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Authorization\AuthorizationMiddleware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * What the authorization middleware of Mezzio answers with the `Authorization`
 * of the package, the same that a site has in its pipeline.
 *
 * It follows the standard (RBAC and ACL of Mezzio): without a user it is a 401,
 * and with a user it is a 403 unless one of the roles of the user is granted, so
 * a user without roles is never granted. What the package adds is, on top of
 * the standard: a protected path without roles in the site and in the route only
 * asks for a user, and a role that nobody declared is not an error.
 */
#[CoversClass(AuthorizationManager::class)]
#[UsesClass(AccessRules::class)]
#[UsesClass(UnauthorizedResponseFactory::class)]
#[UsesClass(User::class)]
final class AuthorizationMiddlewareTest extends TestCase
{
    /**
     * @param list<string>|null $roles The roles of the user, no user if null.
     * @param list<string>|null $routeRoles The roles of the route, no route if
     * null.
     */
    #[DataProvider('cases')]
    public function testTheStatusOfTheResponse(
        int $expected,
        string $path,
        ?array $roles,
        ?array $routeRoles = null
    ): void {
        $this->assertSame($expected, $this->statusOf($path, $roles, $routeRoles));
    }

    /**
     * @return array<string, array{int, string, list<string>|null, 2?: list<string>|null}>
     */
    public static function cases(): array
    {
        return [
            'without a user' => [401, '/admin', null],
            'a user without roles, and the site asks for admin' => [403, '/admin', []],
            'a role that the site asks for' => [200, '/admin', ['admin']],
            'a role that the site does not ask for' => [403, '/admin', ['user']],
            'a role that nobody declared and one that is asked' => [200, '/admin', ['ghost', 'admin']],
            'a role that nobody declared and none that is asked' => [403, '/admin', ['ghost']],
            'a protected path without roles, with a role' => [200, '/private', ['user']],
            'a protected path without roles, with a role that nobody declared' => [200, '/private', ['ghost']],
            'a protected path without roles, a user without roles' => [403, '/private', []],
            'a route with roles, a role that the route has' => [200, '/page', ['editor'], ['editor', 'owner']],
            'a route with roles, a role that the route does not have' => [403, '/page', ['user'], ['editor', 'owner']],
            'a route with roles, a user without roles' => [403, '/page', [], ['editor']],
            'a route with roles, and the site asks for other ones' => [403, '/admin', ['editor'], ['editor']],
            'a route with roles in a protected path without roles' => [403, '/private', ['user'], ['editor']],
            'a route without roles in a public path' => [200, '/page', ['user'], []],
            'no route matched in a public path' => [200, '/page', ['user']],
        ];
    }

    /**
     * @param list<string>|null $roles
     * @param list<string>|null $routeRoles
     */
    private function statusOf(string $path, ?array $roles, ?array $routeRoles): int
    {
        $rules = new AccessRules(['protected_paths' => ['/private', '/admin' => 'admin']]);
        $middleware = new AuthorizationMiddleware(new AuthorizationManager($rules), new UnauthorizedResponseFactory());

        $request = (new ServerRequest())->withUri(new Uri('https://app.test' . $path));
        if ($roles !== null) {
            $request = $request->withAttribute(MezzioUserInterface::class, $this->user($roles));
        }
        if ($routeRoles !== null) {
            $request = $request->withAttribute(
                'derafu.route',
                new RouteMatch(new Route('page', $path, 'PageController@index', [], [], $routeRoles))
            );
        }

        return $middleware->process($request, new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new EmptyResponse(200);
            }
        })->getStatusCode();
    }

    /**
     * @param list<string> $roles
     */
    private function user(array $roles): UserInterface
    {
        return new User('ana@example.com', $roles);
    }
}
