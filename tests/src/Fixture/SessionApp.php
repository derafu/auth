<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\Payload;
use AltchaOrg\Altcha\SolveChallengeOptions;
use Closure;
use Derafu\Auth\Authentication\AuthenticationMiddleware;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Captcha\Provider\AltchaProvider;
use Derafu\Csrf\CsrfSessionMiddleware;
use Derafu\Csrf\SessionCsrfTokenManager;
use Derafu\DataProcessor\ProcessorFactory;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Contract\Renderer\FormRendererInterface;
use Derafu\Form\Factory\FormRendererFactory;
use Derafu\Form\Processor\FormDataProcessor;
use Derafu\Form\Processor\FormRulesResolver;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * What an application has around the authentication: the session, the flash
 * messages and the CSRF token middlewares, with a session persistence in memory.
 * A request goes through them and an action runs inside, as the handler.
 *
 * The forms are protected with a CSRF token, as they are by default, and the
 * login form with a captcha too (ALTCHA, which needs no service): the form data
 * processor and the renderer that it gives (`processor()` and `renderer()`) work
 * with the token manager of the session of the app and with its captcha, and the
 * request of a form that is sent carries the token of its session (`token()`) and
 * what the visitor solved of the captcha, unless it is said that it does not.
 */
final class SessionApp
{
    /**
     * The identifier that a client has in its cookie.
     */
    public const KNOWN = 'id-that-the-client-has';

    /**
     * The secret key of the captcha of the app (ALTCHA, with a cheap challenge).
     */
    public const CAPTCHA_SECRET = 'a-secret-key-of-the-captcha';

    public readonly InMemorySessionPersistence $persistence;

    public readonly SessionCsrfTokenManager $csrf;

    public readonly AltchaProvider $captcha;

    public function __construct()
    {
        $this->persistence = new InMemorySessionPersistence();
        $this->csrf = new SessionCsrfTokenManager();
        $this->captcha = new AltchaProvider(self::CAPTCHA_SECRET, 'en', cost: 10);
        $this->persistence->store[self::KNOWN] = [];
    }

    /**
     * A request of the client that has the session `KNOWN`.
     *
     * @param array<string, string> $query
     * @param array<string, string>|null $body The parsed body of a POST.
     * @param string|null $sid The session of the client, if it is not `KNOWN`.
     * @param array<string, string> $headers The headers of the request.
     * @param string $address The address of the client.
     * @param bool $csrf Whether the body of a form that is sent carries the CSRF
     * token of the session (when the client has one).
     * @param bool $captcha Whether the body of a form that is sent carries what
     * the visitor solved of the captcha.
     * @param string $form The id of the form that is sent (its schema name).
     */
    public function request(
        string $path,
        array $query = [],
        ?array $body = null,
        ?string $sid = null,
        array $headers = [],
        string $address = '203.0.113.7',
        bool $csrf = true,
        bool $captcha = true,
        string $form = 'login'
    ): ServerRequestInterface {
        $request = (new ServerRequest(['REMOTE_ADDR' => $address]))
            ->withUri(new Uri('https://app.test' . $path . ($query === [] ? '' : '?' . http_build_query($query))))
            ->withMethod($body === null ? 'GET' : 'POST')
            ->withQueryParams($query)
            ->withCookieParams(['sid' => $sid ?? self::KNOWN]);

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        if ($body !== null && $csrf && isset($this->persistence->store[$sid ?? self::KNOWN])) {
            $body += [FormInterface::CSRF_FIELD => $this->token($sid, $form)];
        }

        if ($body !== null && $captcha) {
            $body += [$this->captcha->getResponseField() => $this->solvedCaptcha()];
        }

        return $body === null ? $request : $request->withParsedBody($body);
    }

    /**
     * The CSRF token that a client with the session gets for a form.
     *
     * @param string|null $sid The session of the client, `KNOWN` if it is not given.
     * @param string $id The id of the form (its schema name, `login` for the
     * login form).
     */
    public function token(?string $sid = null, string $id = 'login'): string
    {
        $token = '';

        $this->handle(
            $this->request('/', sid: $sid),
            function () use ($id, &$token): void {
                $token = $this->csrf->getToken($id);
            }
        );

        return $token;
    }

    /**
     * What a visitor sends when it solves the captcha of a form: the browser
     * solves the challenge of the widget, which is done here with the library.
     *
     * @param string $formId The id of the form (`login` for the login form).
     */
    public function solvedCaptcha(string $formId = 'login'): string
    {
        preg_match('/ challenge="([^"]*)"/', $this->captcha->getWidget($formId), $matches);
        $challenge = Challenge::fromArray(json_decode(html_entity_decode($matches[1], ENT_QUOTES), true));
        $solution = (new Altcha(hmacSignatureSecret: self::CAPTCHA_SECRET))->solveChallenge(new SolveChallengeOptions(
            algorithm: new Pbkdf2(),
            challenge: $challenge,
        ));

        return (new Payload($challenge, $solution))->toBase64();
    }

    /**
     * A form data processor that checks the CSRF token and the captcha with the
     * ones of the app.
     */
    public function processor(): FormDataProcessor
    {
        return new FormDataProcessor(
            new FormRulesResolver(),
            (new ProcessorFactory())->create(),
            csrfTokenManager: $this->csrf,
            captchaProvider: $this->captcha
        );
    }

    /**
     * A form renderer that writes the CSRF token and the captcha of the app.
     */
    public function renderer(): FormRendererInterface
    {
        return FormRendererFactory::create([
            'csrf_token_manager' => $this->csrf,
            'captcha_provider' => $this->captcha,
        ]);
    }

    /**
     * Handles a request through the middlewares, running the action inside.
     *
     * @param Closure(ServerRequestInterface): mixed $action What the application
     * does with the request: it can give the response, or nothing (an empty
     * response is given).
     */
    public function handle(ServerRequestInterface $request, Closure $action): ResponseInterface
    {
        $handler = new class ($action) implements RequestHandlerInterface {
            public function __construct(private readonly Closure $action)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $response = ($this->action)($request);

                return $response instanceof ResponseInterface ? $response : new Response();
            }
        };

        $csrf = $this->through(new CsrfSessionMiddleware($this->csrf), $handler);
        $flash = $this->through(new FlashMessageMiddleware(), $csrf);

        return (new SessionMiddleware($this->persistence))->process($request, $flash);
    }

    /**
     * A handler that passes the request through a middleware before the handler.
     */
    private function through(MiddlewareInterface $middleware, RequestHandlerInterface $handler): RequestHandlerInterface
    {
        return new class ($middleware, $handler) implements RequestHandlerInterface {
            public function __construct(
                private readonly MiddlewareInterface $middleware,
                private readonly RequestHandlerInterface $handler
            ) {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->middleware->process($request, $this->handler);
            }
        };
    }

    /**
     * Handles a request through the middlewares and the authentication middleware
     * of Mezzio (that gives the user to the request, or the unauthorized
     * response), running the action inside when the user is given.
     *
     * @param Closure(ServerRequestInterface): mixed $action What the application
     * does with the request of a user that was authenticated.
     */
    public function handleAuthenticated(
        ServerRequestInterface $request,
        AuthenticationInterface $authentication,
        Closure $action
    ): ResponseInterface {
        $middleware = new AuthenticationMiddleware($authentication);

        return $this->handle(
            $request,
            function (ServerRequestInterface $request) use ($middleware, $action) {
                return $middleware->process($request, new class ($action) implements RequestHandlerInterface {
                    public function __construct(private readonly Closure $action)
                    {
                    }

                    public function handle(ServerRequestInterface $request): ResponseInterface
                    {
                        $response = ($this->action)($request);

                        return $response instanceof ResponseInterface ? $response : new Response();
                    }
                });
            }
        );
    }

    /**
     * The identifier that the client has to use after a response.
     */
    public function sessionId(ResponseInterface $response): string
    {
        return $response->getHeaderLine('X-Session-Id');
    }
}
