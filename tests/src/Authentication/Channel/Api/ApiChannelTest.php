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
 * An unauthenticated request to the API gets a response with a title and a
 * detail, in the language of the translator, and in English without one.
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
     * @return array<string, mixed>
     */
    private function unauthenticatedResponseOfTheApi(?string $locale): array
    {
        $channel = new ApiChannel(
            new ApiConfiguration(),
            $this->createStub(ApiSchemeInterface::class),
            translator: $locale === null
                ? null
                : TranslatorFactory::create($locale, [], [new AuthTranslationResourceProvider()])
        );

        $response = $channel->unauthorizedResponse(
            (new ServerRequest())->withUri(new Uri('https://example.com/api/items'))
        );

        $this->assertSame(401, $response->getStatusCode());

        return json_decode((string) $response->getBody(), true);
    }

    public function testTheResponseOfTheApiIsInEnglishWithoutATranslator(): void
    {
        $this->assertSame(
            [
                'status' => 401,
                'title' => 'Unauthorized',
                'detail' => 'You need to send valid credentials to access this resource.',
            ],
            $this->unauthenticatedResponseOfTheApi(null)
        );
    }

    public function testTheResponseOfTheApiIsTranslatedWithATranslator(): void
    {
        $this->assertSame(
            [
                'status' => 401,
                'title' => 'No autorizado',
                'detail' => 'Debes enviar credenciales válidas para acceder a este recurso.',
            ],
            $this->unauthenticatedResponseOfTheApi('es')
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
     * request is asked for the response 401.
     */
    private function challengeOf(ApiChannel $channel, string $header): string
    {
        $request = (new ServerRequest())
            ->withUri(new Uri('https://example.com/api/items'))
            ->withHeader('Authorization', $header);

        $channel->identify($request);

        return $channel->unauthorizedResponse($request)->getHeaderLine('WWW-Authenticate');
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

        $this->assertSame('Bearer realm="API"', $channel->unauthorizedResponse($request)->getHeaderLine('WWW-Authenticate'));
    }
}
