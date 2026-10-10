<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication\Channel\Api;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Identification;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\ChannelInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\TooManyAttemptsException;
use Derafu\Translation\TranslatableMessage;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use WeakMap;

/**
 * The API channel: a client sends its credentials in every request, in the
 * header `Authorization`, and nothing is kept (no session, no cookie).
 *
 * The scheme that it reads (`Bearer`, `Basic`) is the one of the provider. A
 * client that sends credentials that are not valid is not authenticated, and it
 * does not go back to a session that it may have: it was not asking for one. One
 * that sends none has nothing to be identified with here, and the next channel
 * that matches is asked (the session of the web), so a path can serve browsers
 * and programs. The header is read only in the paths of the API, and a header of
 * another scheme is ignored, not rejected: a server in front of the application
 * can add its own (a `Basic` for the whole site) and that must not break the
 * sessions of the users.
 *
 * What is answered to a client that is not authenticated is a 401 in JSON, never
 * a redirect to a login that it can not use.
 */
final class ApiChannel implements ChannelInterface
{
    /**
     * Why the credentials of a request were not valid, when the scheme said it. It
     * is kept by the request (that is what the middleware gives again to ask for the
     * response 401) and it goes away with it: the channel does not keep a state
     * between requests.
     *
     * @var WeakMap<ServerRequestInterface, AuthenticationException>|null
     */
    private ?WeakMap $failures = null;

    /**
     * Creates the API channel.
     *
     * @param ApiConfiguration $config The paths and the realm of the API.
     * @param ApiSchemeInterface $scheme The scheme that the provider reads.
     * @param UserInterface $anonymousUser The anonymous user.
     * @param TranslatorInterface|null $translator Translates the title and the
     * detail of the response 401, in the language of the translator. Without it
     * they are in English.
     */
    public function __construct(
        private readonly ApiConfiguration $config,
        private readonly ApiSchemeInterface $scheme,
        private readonly UserInterface $anonymousUser = new AnonymousUser(),
        private readonly ?TranslatorInterface $translator = null
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function name(): string
    {
        return 'api';
    }

    /**
     * {@inheritDoc}
     */
    public function matches(ServerRequestInterface $request): bool
    {
        return $this->config->isApiPath($request->getUri()->getPath());
    }

    /**
     * {@inheritDoc}
     */
    public function identify(ServerRequestInterface $request): Identification
    {
        $credentials = $this->credentialsOf($request);
        if ($credentials === null) {
            return Identification::none();
        }

        $this->scheme->validate();

        try {
            $user = $this->scheme->authenticate($request, $credentials);
        } catch (AuthenticationException $e) {
            $this->failures ??= new WeakMap();
            $this->failures[$request] = $e;
            $user = null;
        }

        return Identification::of($user ?? $this->anonymousUser);
    }

    /**
     * {@inheritDoc}
     *
     * Nothing is public by itself in the API: the access rules decide.
     */
    public function isPublic(ServerRequestInterface $request): bool
    {
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * A JSON response with the status 401, in the language of the translator, and
     * the header `WWW-Authenticate` that says how to authenticate.
     */
    public function unauthorizedResponse(ServerRequestInterface $request): ResponseInterface
    {
        $failure = $this->failures?->offsetExists($request) ? $this->failures[$request] : null;

        // A client that is limited is not told that its credentials are wrong, but
        // when to try again (RFC 6585).
        if ($failure instanceof TooManyAttemptsException) {
            return new JsonResponse(
                [
                    'status' => 429,
                    'title' => $this->translate(new TranslatableMessage('Too Many Requests', [], 'auth')),
                    'detail' => $this->translate(new TranslatableMessage(
                        'Too many failed login attempts. Try again in {minutes, plural, one {# minute} other {# minutes}}.',
                        ['minutes' => (int) ceil($failure->getRetryAfter() / 60)],
                        'auth'
                    )),
                ],
                429,
                ['Retry-After' => (string) $failure->getRetryAfter()]
            );
        }

        $challenge = $this->scheme->challenge(
            $request,
            $this->config->getRealm(),
            $this->credentialsOf($request) !== null,
            $failure?->getMessage()
        );

        return new JsonResponse(
            [
                'status' => 401,
                'title' => $this->translate(new TranslatableMessage('Unauthorized', [], 'auth')),
                'detail' => $this->translate(new TranslatableMessage('You need to send valid credentials to access this resource.', [], 'auth')),
            ],
            401,
            $challenge !== null ? ['WWW-Authenticate' => $challenge] : []
        );
    }

    /**
     * Gets the credentials that a request sends in the header `Authorization`, if
     * they are of the scheme that the provider reads.
     *
     * @return string|null What comes after the scheme, or null if there are none.
     */
    private function credentialsOf(ServerRequestInterface $request): ?string
    {
        // `Scheme credentials`, in one header: two of them, or a scheme with
        // nothing after it, are not credentials.
        $header = trim($request->getHeaderLine('Authorization'));
        if (
            preg_match('/^(\S+)[ \t]+(\S+)$/', $header, $matches)
            && strcasecmp($matches[1], $this->scheme->scheme()) === 0
        ) {
            return $matches[2];
        }

        return null;
    }

    /**
     * Translates a message with the translator, if there is one.
     */
    private function translate(TranslatableMessage $message): string
    {
        return $this->translator !== null
            ? $message->trans($this->translator)
            : (string) $message;
    }
}
