<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Twig;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\Twig\AuthExtension;
use Derafu\Auth\User;
use Derafu\Renderer\Factory\RendererFactory;
use Derafu\Translation\TranslatorFactory;
use Derafu\Twig\Extension\TranslationExtension;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Twig\Extension\AbstractExtension;
use Twig\Extension\GlobalsInterface;

/**
 * The functions of Twig of the authentication, with the names of Symfony, and the
 * menu of the user that uses them with `app.user`.
 */
#[CoversClass(AuthExtension::class)]
#[UsesClass(WebConfiguration::class)]
#[UsesClass(User::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class AuthExtensionTest extends TestCase
{
    private const ROOT = __DIR__ . '/../../..';

    /**
     * A template renderer with the extension and an `app` like the one of
     * `derafu/http` (a class that has `getUser()`).
     */
    private function render(string $template, ?object $user): string
    {
        $app = new class ($user) {
            public function __construct(private readonly ?object $user)
            {
            }

            public function getUser(): ?object
            {
                return $this->user;
            }
        };
        $globals = new class ($app) extends AbstractExtension implements GlobalsInterface {
            public function __construct(private readonly object $app)
            {
            }

            public function getGlobals(): array
            {
                return ['app' => $this->app];
            }
        };

        return RendererFactory::create([
            'engines' => ['twig'],
            'extra' => false,
            'paths' => [self::ROOT . '/resources/templates', self::ROOT . '/vendor/derafu/twig/resources/templates'],
            'extensions' => [
                $globals,
                new TranslationExtension(TranslatorFactory::create('es', ['en'], [new AuthTranslationResourceProvider()]), null, 'es'),
                new AuthExtension(new WebConfiguration()),
            ],
        ])->render($template, []);
    }

    #[Test]
    public function isGrantedIsTheRoleOfTheUserOfTheApp(): void
    {
        $user = new User('ana', ['admin']);
        $template = "{{ is_granted('admin') ? 'yes' : 'no' }}|{{ is_granted('editor') ? 'yes' : 'no' }}|{{ is_granted(['editor', 'admin']) ? 'yes' : 'no' }}";

        $this->assertSame('yes|no|yes', $this->render($this->template($template), $user));
    }

    #[Test]
    public function nobodyIsGrantedAnything(): void
    {
        $template = $this->template("{{ is_granted('admin') ? 'yes' : 'no' }}|{{ is_granted('anonymous') ? 'yes' : 'no' }}");

        $this->assertSame('no|no', $this->render($template, null));
        // The anonymous user stands for nobody, whatever its roles.
        $this->assertSame('no|no', $this->render($template, new AnonymousUser()));
    }

    #[Test]
    public function thePathsAreTheOnesOfTheConfiguration(): void
    {
        $template = $this->template('{{ login_path() }}|{{ logout_path() }}|{{ profile_path() }}');

        $this->assertSame('/auth/login|/auth/logout|/auth/profile', $this->render($template, null));
    }

    #[Test]
    public function theMenuOffersTheLoginToAVisitor(): void
    {
        $html = $this->render('partials/auth-menu', null);

        $this->assertStringContainsString('href="/auth/login"', $html);
        $this->assertStringContainsString('Iniciar sesión', $html);
        $this->assertStringNotContainsString('/auth/logout', $html);
    }

    #[Test]
    public function theMenuOffersTheProfileAndTheLogoutToAUser(): void
    {
        $html = $this->render('partials/auth-menu', new User('ana', [], ['name' => 'Ana Pérez']));

        $this->assertStringContainsString('Ana Pérez', $html);
        $this->assertStringContainsString('href="/auth/profile"', $html);
        // The logout is a POST, never a link.
        $this->assertMatchesRegularExpression('#<form method="post" action="/auth/logout">#', $html);
        $this->assertStringContainsString('Cerrar sesión', $html);
        $this->assertStringNotContainsString('href="/auth/login"', $html);
    }

    #[Test]
    public function theMenuUsesTheIdentityOfAUserWithoutName(): void
    {
        $this->assertStringContainsString('beto', $this->render('partials/auth-menu', new User('beto')));
    }

    /**
     * The template of a test is a file in the temporary directory, so the renderer
     * that is used is the real one.
     */
    private function template(string $source): string
    {
        $path = tempnam(sys_get_temp_dir(), 'auth-extension-') . '.html.twig';
        file_put_contents($path, $source);
        register_shutdown_function(static fn () => @unlink($path));

        return $path;
    }
}
