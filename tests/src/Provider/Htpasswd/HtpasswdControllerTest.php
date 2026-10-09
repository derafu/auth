<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Htpasswd;

use Derafu\Auth\Authentication\Channel\Web\FormManager;
use Derafu\Auth\Authentication\Channel\Web\SessionManager;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Provider\Htpasswd\HtpasswdUserRepository;
use Derafu\Auth\Provider\Htpasswd\Web\HtpasswdController;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Factory\TranslatingFormFactory;
use Derafu\Form\Renderer\FormTwigExtension;
use Derafu\Form\Translation\FormTranslationResourceProvider;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\Renderer\Factory\RendererFactory;
use Derafu\TestsAuth\Fixture\HtpasswdFile;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use Derafu\Translation\TranslatorFactory;
use Derafu\Twig\Extension\TranslationExtension;
use Laminas\Diactoros\Response\RedirectResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * The login page is rendered with the real renderer, the real form and its
 * translations: the form of the login, and the messages that the authentication
 * left for the next request.
 */
#[CoversClass(HtpasswdController::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationManager::class)]
#[UsesClass(\Derafu\Auth\Authentication\Identification::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\Flash::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authorization\AccessRules::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\Scheme\BasicScheme::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\Api\HtpasswdBasicScheme::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\FormManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\Web\HtpasswdWebFlow::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\HtpasswdUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\Web\Form\LoginForm::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\SessionManager::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationMiddleware::class)]
final class HtpasswdControllerTest extends TestCase
{
    private SessionApp $app;

    private HtpasswdFile $file;

    private AuthenticationInterface $authentication;

    private HtpasswdController $controller;

    protected function setUp(): void
    {
        $root = dirname(__DIR__, 4);
        $this->app = new SessionApp();
        $this->file = new HtpasswdFile();

        $config = $this->file->config([
            'enabled' => true,
            'protected_paths' => ['/private'],
            'unauthorized_redirect_path' => '/auth/login',
        ]);

        $translator = TranslatorFactory::create('es', ['en'], [
            new AuthTranslationResourceProvider(),
            new FormTranslationResourceProvider(),
        ]);

        $formManager = new FormManager(
            new TranslatingFormFactory(
                new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
                $translator
            ),
            $this->app->processor(),
            $config
        );

        $this->authentication = Stack::htpasswd(
            new HtpasswdUserRepository($config),
            $config,
            new SessionManager(),
            $formManager
        );

        // The routing is an application's: only its function `path` is declared.
        $routing = new class () extends AbstractExtension {
            public function getFunctions(): array
            {
                return [new TwigFunction('path', fn (string $name): string => '/' . str_replace('_', '/', $name))];
            }
        };

        $this->controller = new HtpasswdController(
            RendererFactory::create([
                'engines' => ['twig'],
                'extra' => false,
                'paths' => [
                    $root . '/resources/templates',
                    $root . '/tests/fixtures/templates',
                    $root . '/vendor/derafu/twig/resources/templates',
                    $root . '/vendor/derafu/form/resources/templates',
                ],
                'extensions' => [
                    $routing,
                    new TranslationExtension($translator, null, 'es'),
                    new FormTwigExtension($this->app->renderer()),
                ],
            ]),
            $formManager,
            Stack::webOf($config),
            new SessionManager()
        );
    }

    protected function tearDown(): void
    {
        $this->file->remove();
    }

    /**
     * The page of the login, for a request that goes through the middlewares.
     */
    private function page(ServerRequestInterface $request): string
    {
        $page = '';
        $this->app->handle($request, function (ServerRequestInterface $request) use (&$page) {
            $page = $this->controller->login($request);
        });

        return $page;
    }

    #[Test]
    public function theLoginPageHasTheFormWithTheFieldsOfTheLogin(): void
    {
        $page = $this->page($this->app->request('/auth/login')->withParsedBody([]));

        $this->assertStringContainsString('action="/auth/login"', $page);
        $this->assertStringContainsString('method="POST"', $page);
        $this->assertStringContainsString('name="username"', $page);
        $this->assertStringContainsString('name="password"', $page);
        $this->assertStringContainsString('type="password"', $page);
        $this->assertStringContainsString('<button type="submit"', $page);
    }

    #[Test]
    public function theLoginPageHasTheCsrfTokenOfTheSession(): void
    {
        $page = $this->page($this->app->request('/auth/login'));

        $this->assertSame(1, preg_match('/name="_token" value="([^"]+)"/', $page, $matches));

        $valid = false;
        $this->app->handle($this->app->request('/'), function () use ($matches, &$valid): void {
            $valid = $this->app->csrf->isValid('login', $matches[1]);
        });
        $this->assertTrue($valid);
    }

    #[Test]
    public function theLoginPageHasTheCaptchaOfTheApplicationForTheLoginForm(): void
    {
        $page = $this->page($this->app->request('/auth/login'));

        $this->assertStringContainsString('<altcha-widget', $page);
        $this->assertSame(1, preg_match('/ challenge="([^"]*)"/', $page, $matches));
        $challenge = json_decode(html_entity_decode($matches[1], ENT_QUOTES), true);
        $this->assertSame(['form' => 'login'], $challenge['parameters']['data']);
        $this->assertStringContainsString('name="altcha"', $page);
    }

    #[Test]
    public function theLoginPageOfARequestWithoutABodyHasTheFormToo(): void
    {
        // The parsed body of the request is null (some PSR-7 implementations).
        $page = $this->page($this->app->request('/auth/login'));

        $this->assertStringContainsString('name="username"', $page);
        $this->assertStringContainsString('name="password"', $page);
    }

    #[Test]
    public function theFieldsOfALoginPageThatWasNotSubmittedHaveNoErrors(): void
    {
        $page = $this->page($this->app->request('/auth/login')->withParsedBody([]));

        $this->assertStringNotContainsString('has-error', $page);
        $this->assertStringNotContainsString('invalid-feedback', $page);
    }

    #[Test]
    public function theLoginPageIsInTheLanguageOfTheTranslator(): void
    {
        $page = $this->page($this->app->request('/auth/login')->withParsedBody([]));

        $this->assertStringContainsString('<h1 class="border-bottom mb-4">Iniciar sesión</h1>', $page);
        $this->assertStringContainsString('>Usuario</label>', $page);
        $this->assertStringContainsString('>Contraseña</label>', $page);
        $this->assertStringNotContainsString('>Username</label>', $page);
    }

    #[Test]
    public function theLoginPageFillsTheFormWithTheSubmittedData(): void
    {
        $page = $this->page(
            $this->app->request('/auth/login')->withParsedBody(['username' => 'ana'])
        );

        $this->assertStringContainsString('value="ana"', $page);
    }

    #[Test]
    public function theLoginPageShowsTheMessageThatTheAuthenticationLeft(): void
    {
        // A protected page without a user: the authentication redirects to the
        // login and leaves a message for the next request.
        $this->app->handle(
            $this->app->request('/private/page'),
            function (ServerRequestInterface $request) {
                $this->authentication->unauthorizedResponse($request);
            }
        );

        $page = $this->page($this->app->request('/auth/login')->withParsedBody([]));

        $this->assertStringContainsString(
            'Debes iniciar sesión para acceder a la página solicitada /private/page',
            $page
        );
        $this->assertStringContainsString('alert-danger', $page);
    }

    #[Test]
    public function theLogoutThatTheAuthenticationDidNotHandleOnlyRedirects(): void
    {
        $response = $this->controller->logout($this->app->request('/auth/logout'));

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/', $response->getHeaderLine('Location'));
    }

    /**
     * The login page asked in a request that goes through the authentication.
     *
     * @return string|\Psr\Http\Message\ResponseInterface
     */
    private function loginPageThroughTheAuthentication(?string $sid, string $path = '/auth/login'): mixed
    {
        $result = null;
        $this->app->handleAuthenticated(
            $this->app->request($path, sid: $sid),
            $this->authentication,
            function (ServerRequestInterface $request) use (&$result): void {
                $result = $this->controller->login($request->withParsedBody([]));
            }
        );

        return $result;
    }

    #[Test]
    public function aUserThatLoggedInGoesToThePageThatWasRequested(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['identity' => 'ana'],
            'auth_checked_at' => time(),
            'auth_redirect' => '/private/page?tab=2',
        ];

        $response = $this->loginPageThroughTheAuthentication(SessionApp::KNOWN);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame('/private/page?tab=2', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function aUserThatLoggedInGoesToThePageThatFollowsTheLoginWhenNoPageWasRequested(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['identity' => 'ana'],
            'auth_checked_at' => time(),
        ];

        $response = $this->loginPageThroughTheAuthentication(SessionApp::KNOWN);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame('/', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function theRedirectAfterTheLoginHappensOnce(): void
    {
        $this->app->persistence->store[SessionApp::KNOWN] = [
            'user' => ['identity' => 'ana'],
            'auth_checked_at' => time(),
            'auth_redirect' => '/private/page',
        ];

        $this->loginPageThroughTheAuthentication(SessionApp::KNOWN);

        $this->assertArrayNotHasKey('auth_redirect', $this->app->persistence->store[SessionApp::KNOWN]);
    }

    #[Test]
    public function aUserThatIsNotLoggedInSeesTheLoginPage(): void
    {
        $page = $this->loginPageThroughTheAuthentication(SessionApp::KNOWN);

        $this->assertIsString($page);
        $this->assertStringContainsString('name="username"', $page);
    }

    #[Test]
    public function theLoginPageWithoutMessagesShowsNoAlert(): void
    {
        $page = $this->page($this->app->request('/auth/login')->withParsedBody([]));

        $this->assertStringNotContainsString('alert', $page);
    }
}
