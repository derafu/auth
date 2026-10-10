<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authentication\Channel\Api;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Channel\Api\ApiChannel;
use Derafu\Auth\Authentication\Channel\Api\ApiConfiguration;
use Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Translation\TranslatorFactory;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * An unauthenticated request to the API gives an `AuthenticationException`, with
 * a message that is translatable (in English as it is, in the language of a
 * translator that reads it) and, when the scheme can tell why, a challenge that
 * says it.
 */
#[CoversClass(ApiChannel::class)]
#[UsesClass(ApiConfiguration::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(BearerScheme::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(\Derafu\Auth\Authentication\Identification::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class ApiChannelTest extends TestCase
{
    /**
     * The exception of a request without credentials: `unauthorizedResponse()`
     * always throws, so this is what the middleware would let through.
     */
    private function unauthorizedException(): AuthenticationException
    {
        $channel = new ApiChannel(new ApiConfiguration(), $this->createStub(ApiSchemeInterface::class));

        try {
            $channel->unauthorizedResponse(
                (new ServerRequest())->withUri(new Uri('https://example.com/api/items'))
            );
        } catch (AuthenticationException $e) {
            return $e;
        }

        $this->fail('unauthorizedResponse() did not throw.');
    }

    public function testWithoutCredentialsTheExceptionIs401InEnglishByDefault(): void
    {
        $exception = $this->unauthorizedException();

        $this->assertSame(401, $exception->getCode());
        $this->assertSame(
            'You need to send valid credentials to access this resource.',
            $exception->getMessage()
        );
    }

    public function testTheExceptionIsTranslatedByWhoeverCatchesIt(): void
    {
        $translator = TranslatorFactory::create('es', [], [new AuthTranslationResourceProvider()]);

        $this->assertSame(
            'Debes enviar credenciales válidas para acceder a este recurso.',
            $this->unauthorizedException()->trans($translator)
        );
    }

    /**
     * A `Bearer` scheme that says why a token is not valid, with what it is given.
     *
     * @param \Closure(string): ?UserInterface $authenticate
     */
    private function bearer(\Closure $authenticate): BearerScheme
    {
        return new class ($authenticate) extends BearerScheme {
            public function __construct(private readonly \Closure $authenticate)
            {
            }

            public function validate(): void
            {
            }

            protected function authenticateToken(string $token): ?UserInterface
            {
                return ($this->authenticate)($token);
            }
        };
    }

    /**
     * What the middleware does: the channel identifies the request, and the same
     * request is asked for the response 401, which is the challenge of the
     * exception that it throws.
     */
    private function challengeOf(ApiChannel $channel, string $header): string
    {
        $request = (new ServerRequest())
            ->withUri(new Uri('https://example.com/api/items'))
            ->withHeader('Authorization', $header);

        $channel->identify($request);

        try {
            $channel->unauthorizedResponse($request);
        } catch (AuthenticationException $e) {
            return $e->getHeaders()['WWW-Authenticate'] ?? '';
        }

        $this->fail('unauthorizedResponse() did not throw.');
    }

    public function testTheReasonThatTheSchemeGivesIsInTheChallenge(): void
    {
        $channel = new ApiChannel(
            new ApiConfiguration(),
            $this->bearer(fn () => throw new AuthenticationException('The token has expired.', 401))
        );

        $this->assertSame(
            'Bearer realm="API", error="invalid_token", error_description="The token has expired."',
            $this->challengeOf($channel, 'Bearer abc')
        );
    }

    public function testTheReasonOnlyHasWhatAHeaderCanHave(): void
    {
        // RFC 6750, 3: printable ASCII, with no quotes and no backslashes.
        $channel = new ApiChannel(
            new ApiConfiguration(),
            $this->bearer(fn () => throw new AuthenticationException("Not \"valid\" \\ token: contrase\u{00f1}a\r\nX-Evil: 1", 401))
        );

        $this->assertSame(
            'Bearer realm="API", error="invalid_token", error_description="Not valid  token: contraseaX-Evil: 1"',
            $this->challengeOf($channel, 'Bearer abc')
        );
    }

    public function testATokenWithoutAReasonHasNoDescription(): void
    {
        $channel = new ApiChannel(new ApiConfiguration(), $this->bearer(fn () => null));

        $this->assertSame('Bearer realm="API", error="invalid_token"', $this->challengeOf($channel, 'Bearer abc'));
    }

    public function testTheReasonOfARequestIsNotThePreviousOne(): void
    {
        // The same channel serves every request: what one request says is not what
        // the next one is told.
        $channel = new ApiChannel(
            new ApiConfiguration(),
            $this->bearer(fn (string $token) => $token === 'expired'
                ? throw new AuthenticationException('The token has expired.', 401)
                : null)
        );

        $this->assertStringContainsString('error_description="The token has expired."', $this->challengeOf($channel, 'Bearer expired'));
        $this->assertSame('Bearer realm="API", error="invalid_token"', $this->challengeOf($channel, 'Bearer other'));
    }

    public function testWithoutCredentialsThereIsNoErrorAtAll(): void
    {
        $channel = new ApiChannel(
            new ApiConfiguration(),
            $this->bearer(fn () => throw new AuthenticationException('The token has expired.', 401))
        );

        $request = (new ServerRequest())->withUri(new Uri('https://example.com/api/items'));
        $channel->identify($request);

        try {
            $channel->unauthorizedResponse($request);
        } catch (AuthenticationException $e) {
            $this->assertSame('Bearer realm="API"', $e->getHeaders()['WWW-Authenticate'] ?? '');

            return;
        }

        $this->fail('unauthorizedResponse() did not throw.');
    }
}
