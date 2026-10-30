<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth;

use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\AuthorizationException;
use Derafu\TestsAuth\Fixture\AuthApplication;
use Derafu\TestsAuth\Fixture\HtpasswdFile;
use IteratorIterator;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use LogicException;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Exercises the opt-in HTTP tags through real authentication and authorization.
 */
#[CoversNothing]
final class HttpServicesTest extends TestCase
{
    /** @var array<string, string|false> */
    private array $environment = [];

    private HtpasswdFile $users;

    protected function setUp(): void
    {
        $this->users = new HtpasswdFile(['ana' => 'secret', 'bob' => 'secret']);
        $this->users->groups(['admin' => ['ana'], 'reader' => ['bob']]);
        foreach ([
            'AUTH_PROVIDER' => 'htpasswd',
            'AUTH_ENABLED' => 'true',
            'AUTH_API_PATHS' => '["/api"]',
            'AUTH_PROTECTED_PATHS' => '{"/api/private":["admin"]}',
            'AUTH_HTPASSWD_PATH' => $this->users->path(),
            'AUTH_HTPASSWD_GROUP_PATH' => $this->users->groupPath(),
        ] as $name => $value) {
            $this->environment[$name] = getenv($name);
            putenv($name . '=' . $value);
        }
    }

    protected function tearDown(): void
    {
        $this->users->remove();
        foreach ($this->environment as $name => $value) {
            putenv($value === false ? $name : $name . '=' . $value);
        }
    }

    public function testBaseServicesDoNotActivateTheDerafuHttpPipeline(): void
    {
        self::assertSame([], AuthApplication::container()->findTaggedServiceIds('derafu_http.middleware'));
    }

    public function testPublicRequestsReachTheHandlerAsAnonymous(): void
    {
        $response = $this->pipeline()->handle($this->request('/public'));
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertTrue($body['anonymous']);
    }

    public function testAuthenticationPrecedesAuthorizationAndPreservesTheUser(): void
    {
        $response = $this->pipeline()->handle($this->request('/api/private', 'ana', 'secret'));
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertSame('ana', $body['identity']);
        self::assertFalse($body['anonymous']);
    }

    public function testProtectedRequestsWithoutCredentialsAreChallenged(): void
    {
        $pipeline = $this->pipeline();
        try {
            $pipeline->handle($this->request('/api/private'));
            self::fail('Authentication must reject a protected request without credentials.');
        } catch (AuthenticationException $exception) {
            self::assertSame(401, $exception->getCode());
            $challenge = $exception->getHeaders()['WWW-Authenticate'] ?? '';
            self::assertIsString($challenge);
            self::assertStringStartsWith('Basic ', $challenge);
        }
    }

    public function testIncorrectCredentialsDoNotReachTheHandler(): void
    {
        $pipeline = $this->pipeline();
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(401);
        $pipeline->handle($this->request('/api/private', 'ana', 'wrong'));
    }

    public function testAuthenticatedUsersWithoutTheRequiredRoleAreRejected(): void
    {
        $pipeline = $this->pipeline();
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionCode(403);
        $pipeline->handle($this->request('/api/private', 'bob', 'secret'));
    }

    private function request(string $path, ?string $username = null, string $password = ''): ServerRequestInterface
    {
        $request = (new ServerRequest())->withUri(new Uri('https://app.example.com' . $path));

        return $username === null ? $request : $request->withHeader('Authorization', 'Basic ' . base64_encode($username . ':' . $password));
    }

    /**
     * The YAML supplies every Auth service and the tagged middleware iterator;
     * these PSR-15 adapters only provide the consuming pipeline and its action.
     */
    private function pipeline(): RequestHandlerInterface
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.project_dir', dirname(__DIR__, 2));
        AuthApplication::load($container, 'application-http.yaml');
        $container->compile(true);
        $middlewares = $container->get('test.http_middlewares');
        self::assertInstanceOf(IteratorIterator::class, $middlewares);

        $handler = new class () implements RequestHandlerInterface {
            /**
             * {@inheritDoc}
             */
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $user = $request->getAttribute(MezzioUserInterface::class);
                if (!$user instanceof UserInterface) {
                    throw new LogicException('Authentication must add the user before dispatch.');
                }

                return new JsonResponse(['identity' => $user->getIdentity(), 'anonymous' => $user->isAnonymous()]);
            }
        };
        foreach (array_reverse(iterator_to_array($middlewares, false)) as $middleware) {
            self::assertInstanceOf(MiddlewareInterface::class, $middleware);
            $handler = new class ($middleware, $handler) implements RequestHandlerInterface {
                public function __construct(
                    private readonly MiddlewareInterface $middleware,
                    private readonly RequestHandlerInterface $next,
                ) {
                }

                /**
                 * {@inheritDoc}
                 */
                public function handle(ServerRequestInterface $request): ResponseInterface
                {
                    return $this->middleware->process($request, $this->next);
                }
            };
        }

        return $handler;
    }
}
