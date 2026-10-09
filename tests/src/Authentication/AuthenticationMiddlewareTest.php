<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authentication;

use Derafu\Auth\Authentication\AuthenticationMiddleware;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\User;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use Mezzio\Authentication\UserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The middleware puts the user that the authentication gives in the request, with
 * the name of the interface of Mezzio, or answers with the response of the
 * authentication when it gives none.
 */
#[CoversClass(AuthenticationMiddleware::class)]
#[UsesClass(User::class)]
final class AuthenticationMiddlewareTest extends TestCase
{
    private function request(): ServerRequestInterface
    {
        return (new ServerRequest())->withUri(new Uri('https://app.test/page'));
    }

    #[Test]
    public function theUserGoesInTheRequestAndTheRequestGoesOn(): void
    {
        $user = new User('ana@example.com', ['admin']);
        $authentication = $this->createStub(AuthenticationInterface::class);
        $authentication->method('authenticate')->willReturn($user);

        $handler = new class () implements RequestHandlerInterface {
            public mixed $seen = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->seen = $request->getAttribute(UserInterface::class);

                return new EmptyResponse(200);
            }
        };

        $response = (new AuthenticationMiddleware($authentication))->process($this->request(), $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($user, $handler->seen);
    }

    #[Test]
    public function aRequestThatIsNotAuthenticatedGetsTheResponseOfTheAuthenticationAndDoesNotGoOn(): void
    {
        $authentication = $this->createStub(AuthenticationInterface::class);
        $authentication->method('authenticate')->willReturn(null);
        $authentication->method('unauthorizedResponse')->willReturn(new EmptyResponse(302, ['Location' => '/auth/login']));

        $response = (new AuthenticationMiddleware($authentication))->process(
            $this->request(),
            new class () implements RequestHandlerInterface {
                public function handle(ServerRequestInterface $request): ResponseInterface
                {
                    throw new \LogicException('The request went on.');
                }
            }
        );

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/auth/login', $response->getHeaderLine('Location'));
    }
}
