<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Abstract;

use Derafu\Auth\Abstract\AbstractProviderAuthentication;
use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Exception\FormException;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\User;
use Derafu\TestsAuth\Fixture\FlashAuthentication;
use Derafu\Translation\TranslatableMessage;
use Derafu\Translation\TranslatorFactory;
use Derafu\Twig\Extension\TranslationExtension;
use Derafu\Twig\Service\TwigService;
use Laminas\Diactoros\ServerRequest;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Flash\FlashMessages;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * The flash messages of the package are messages as data (id, parameters and
 * domain), and they are translated when they are shown.
 *
 * It is tested with the session of Mezzio, which keeps only JSON: what the next
 * request reads is what the session gave back, and then it is rendered by the
 * partial of the package, in English and in Spanish.
 */
#[CoversClass(AbstractProviderAuthentication::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(User::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
#[UsesClass(FormException::class)]
final class AbstractProviderAuthenticationFlashTest extends TestCase
{
    private Session $session;

    private FlashAuthentication $authentication;

    protected function setUp(): void
    {
        $this->session = new Session([]);

        $this->authentication = new FlashAuthentication(
            $this->createStub(ConfigurationInterface::class),
            $this->createStub(SessionManagerInterface::class)
        );
    }

    private function request(): ServerRequest
    {
        return (new ServerRequest())->withAttribute(
            FlashMessageMiddleware::FLASH_ATTRIBUTE,
            FlashMessages::createFromSession($this->session)
        );
    }

    /**
     * What the next request reads: the session gave back JSON.
     *
     * @return array<string, mixed>
     */
    private function nextRequestFlashes(): array
    {
        return FlashMessages::createFromSession($this->session)->getFlashes();
    }

    private function render(string $template, array $context, bool $translated): string
    {
        $root = dirname(__DIR__, 3);
        $application = new class () extends AbstractExtension {
            public function getFunctions(): array
            {
                return array_map(
                    fn (string $name) => new TwigFunction($name, fn () => '', ['is_safe' => ['html']]),
                    ['path', 'form_start', 'form_element', 'form_csrf', 'form_end']
                );
            }
        };

        $extensions = [$application];
        if ($translated) {
            $extensions[] = new TranslationExtension(
                TranslatorFactory::create('es', [], [new AuthTranslationResourceProvider()]),
                null,
                'es'
            );
        }

        return (new TwigService([
            'extra' => false,
            'paths' => [
                $root . '/resources/templates',
                $root . '/tests/fixtures/templates',
                $root . '/vendor/derafu/twig/resources/templates',
            ],
            'extensions' => $extensions,
        ]))->getTwig()->render($template, $context);
    }

    /**
     * @return array<string, array{callable(self, ServerRequestInterface): void, string, string}>
     */
    public static function provideFlashMessages(): array
    {
        return [
            'a success' => [
                fn (self $test, ServerRequestInterface $request) => $test->authentication->success($request, 'Successfully logged in.'),
                'Successfully logged in.',
                'Sesión iniciada correctamente.',
            ],
            'an error with a parameter' => [
                fn (self $test, ServerRequestInterface $request) => $test->authentication->error(
                    $request,
                    'You must be logged in to access the requested page {path}',
                    ['path' => '/admin']
                ),
                'You must be logged in to access the requested page /admin',
                'Debes iniciar sesión para acceder a la página solicitada /admin',
            ],
            'the message of an exception, of another domain' => [
                fn (self $test, ServerRequestInterface $request) => $test->authentication->error(
                    $request,
                    (new FormException('Invalid form data.', 400))->getTranslatableMessage()
                ),
                'Invalid form data.',
                'Datos de formulario inválidos.',
            ],
            'a message that is already made' => [
                fn (self $test, ServerRequestInterface $request) => $test->authentication->success(
                    $request,
                    new TranslatableMessage('The session has been closed successfully.', [], 'auth')
                ),
                'The session has been closed successfully.',
                'La sesión se cerró correctamente.',
            ],
        ];
    }

    #[DataProvider('provideFlashMessages')]
    public function testAFlashMessageSurvivesTheSessionAndIsTranslatedWhenItIsShown(
        callable $flash,
        string $english,
        string $spanish
    ): void {
        $flash($this, $this->request());

        $flashes = $this->nextRequestFlashes();
        $this->assertCount(1, $flashes);

        $html = $this->render('partials/flash-messages.html.twig', ['app' => ['flashes' => $flashes]], false);
        $this->assertStringContainsString($english, html_entity_decode($html));

        $html = $this->render('partials/flash-messages.html.twig', ['app' => ['flashes' => $flashes]], true);
        $this->assertStringContainsString($spanish, html_entity_decode($html));
        $this->assertStringNotContainsString($english, html_entity_decode($html));
    }

    public function testWhatTheSessionKeepsIsTheDataOfTheMessage(): void
    {
        $this->authentication->error(
            $this->request(),
            'You must be logged in to access the requested page {path}',
            ['path' => '/admin']
        );

        $this->assertSame(
            [
                'error' => [
                    'message' => 'You must be logged in to access the requested page {path}',
                    'parameters' => ['path' => '/admin'],
                    'domain' => 'auth',
                    'defaultLocale' => null,
                ],
            ],
            $this->nextRequestFlashes()
        );
    }

    /**
     * A flash message that is shown in the same request is not read from the
     * session: it is the message itself, and it is shown the same.
     */
    public function testAFlashMessageThatIsShownInTheSameRequestIsTranslatedToo(): void
    {
        $request = $this->request();
        $this->authentication->error($request, 'Invalid identity or password.', now: true);

        $flashes = $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE)->getFlashes();

        $html = $this->render('partials/flash-messages.html.twig', ['app' => ['flashes' => $flashes]], true);
        $this->assertStringContainsString('Identidad o contraseña inválida.', $html);
    }

    /**
     * Other parts of an application put texts in the session: the partial shows
     * them as they are.
     */
    public function testATextThatIsNotOfThePackageIsShownAsItIs(): void
    {
        $html = $this->render('partials/flash-messages.html.twig', ['app' => ['flashes' => ['info' => 'Saved.']]], true);

        $this->assertStringContainsString('Saved.', $html);
    }

    /**
     * The parameters of a message are data, and they can come from a user: they
     * are escaped before they are put in the text.
     */
    public function testTheParametersOfAMessageAreEscaped(): void
    {
        $this->authentication->error(
            $this->request(),
            'You must be logged in to access the requested page {path}',
            ['path' => "/<script>alert('x')</script>&"]
        );

        $html = $this->render('partials/flash-messages.html.twig', ['app' => ['flashes' => $this->nextRequestFlashes()]], true);

        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringContainsString('Debes iniciar sesión para acceder a la página solicitada', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
    }

    /**
     * The text of a message is trusted, so it can have a link, a list or a line
     * break.
     */
    public function testTheTextOfAMessageCanHaveHtml(): void
    {
        $this->authentication->success(
            $this->request(),
            new TranslatableMessage('Account created. <a href="/login">Log in</a><ul><li>One</li></ul>', [], 'auth')
        );

        $html = $this->render('partials/flash-messages.html.twig', ['app' => ['flashes' => $this->nextRequestFlashes()]], true);

        $this->assertStringContainsString('<a href="/login">Log in</a><ul><li>One</li></ul>', $html);
    }

    public function testAParameterThatIsNotATextIsNotChanged(): void
    {
        $this->authentication->success(
            $this->request(),
            new TranslatableMessage('{count, plural, one {# item} other {# items}} saved.', ['count' => 5], 'auth')
        );

        $html = $this->render('partials/flash-messages.html.twig', ['app' => ['flashes' => $this->nextRequestFlashes()]], false);

        $this->assertStringContainsString('5 items saved.', $html);
    }

    /**
     * A text that another part of the application put in the session is data
     * too: it is escaped, and its line breaks are kept.
     */
    public function testATextThatIsNotOfThePackageIsEscapedAndKeepsItsLineBreaks(): void
    {
        $html = $this->render(
            'partials/flash-messages.html.twig',
            ['app' => ['flashes' => ['info' => "Line 1\n<b>bold</b>"]]],
            true
        );

        $this->assertStringContainsString('Line 1<br />', $html);
        $this->assertStringContainsString('&lt;b&gt;bold&lt;/b&gt;', $html);
        $this->assertStringNotContainsString('<b>', $html);
    }

    public function testTheLoginPageIsTranslated(): void
    {
        $context = ['form' => (object) ['uiSchema' => []], 'app' => ['flashes' => []]];

        $english = $this->render('auth/login.html.twig', $context, false);
        $spanish = $this->render('auth/login.html.twig', $context, true);

        $this->assertSame(2, substr_count($english, 'Login'));
        $this->assertSame(2, substr_count($spanish, 'Iniciar sesión'));
        $this->assertStringNotContainsString('Login', $spanish);
    }
}
