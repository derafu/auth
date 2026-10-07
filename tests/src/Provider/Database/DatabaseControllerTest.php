<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Database;

use Derafu\Auth\FormManager;
use Derafu\Auth\Provider\Database\DatabaseAuthentication;
use Derafu\Auth\Provider\Database\DatabaseController;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\SessionManager;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Factory\TranslatingFormFactory;
use Derafu\Form\Renderer\FormTwigExtension;
use Derafu\Form\Translation\FormTranslationResourceProvider;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\Renderer\Factory\RendererFactory;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\UsersDatabase;
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
#[CoversClass(DatabaseController::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\FormManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\DatabaseAuthentication::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\DatabaseConfiguration::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\DatabaseUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Database\Form\LoginForm::class)]
#[UsesClass(\Derafu\Auth\SessionManager::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class DatabaseControllerTest extends TestCase
{
    private SessionApp $app;

    private UsersDatabase $database;

    private DatabaseAuthentication $authentication;

    private DatabaseController $controller;

    protected function setUp(): void
    {
        $root = dirname(__DIR__, 4);
        $this->app = new SessionApp();
        $this->database = new UsersDatabase();

        $config = $this->database->config([
            'enabled' => true,
            'protected_paths' => ['/private'],
            'unauthorized_redirect_route' => '/auth/login',
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

        $this->authentication = new DatabaseAuthentication(
            new DatabaseUserRepository($config),
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

        $this->controller = new DatabaseController(
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
            $config,
            new SessionManager()
        );
    }

    protected function tearDown(): void
    {
        $this->database->remove();
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
        $this->assertStringContainsString('name="email"', $page);
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

        $this->assertStringContainsString('name="email"', $page);
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
            $this->app->request('/auth/login')->withParsedBody(['email' => 'ana@example.com'])
        );

        $this->assertStringContainsString('value="ana&#x40;example.com"', $page);
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
            'user' => ['identity' => 'ana@example.com', 'roles' => [], 'details' => []],
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
            'user' => ['identity' => 'ana@example.com', 'roles' => [], 'details' => []],
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
            'user' => ['identity' => 'ana@example.com', 'roles' => [], 'details' => []],
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
        $this->assertStringContainsString('name="email"', $page);
    }

    #[Test]
    public function theLoginPageWithoutMessagesShowsNoAlert(): void
    {
        $page = $this->page($this->app->request('/auth/login')->withParsedBody([]));

        $this->assertStringNotContainsString('alert', $page);
    }
}
