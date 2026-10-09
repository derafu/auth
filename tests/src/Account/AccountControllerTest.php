<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Account;

use Derafu\Auth\Account\AccountController;
use Derafu\Auth\Account\ApiToken;
use Derafu\Auth\Account\BasicAccount;
use Derafu\Auth\Account\PhpSessionDetails;
use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Channel\Web\Flash;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Authentication\SameOrigin;
use Derafu\Auth\Contract\AccountInterface;
use Derafu\Auth\Contract\ApiTokenManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\AuthorizationException;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\Twig\AuthExtension;
use Derafu\Auth\User;
use Derafu\Renderer\Factory\RendererFactory;
use Derafu\Translation\TranslatableMessage;
use Derafu\Translation\TranslatorFactory;
use Derafu\Twig\Extension\TranslationExtension;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Flash\FlashMessagesInterface;
use Mezzio\Session\Session;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * The profile and the tokens of the API, the same for every provider: the page is
 * rendered with the real renderer and its translations, what the provider does not
 * have (the tokens) is not offered, and what changes something only accepts a
 * request of the site itself.
 */
#[CoversClass(AccountController::class)]
#[CoversClass(BasicAccount::class)]
#[CoversClass(PhpSessionDetails::class)]
#[CoversClass(SameOrigin::class)]
#[UsesClass(ApiToken::class)]
#[UsesClass(AuthExtension::class)]
#[UsesClass(WebConfiguration::class)]
#[UsesClass(User::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(Flash::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(AuthorizationException::class)]
final class AccountControllerTest extends TestCase
{
    private const ROOT = __DIR__ . '/../../..';

    private function controller(?AccountInterface $account = null): AccountController
    {
        $translator = TranslatorFactory::create('es', ['en'], [new AuthTranslationResourceProvider()]);

        // The routing is an application's: only its function `path` is declared.
        $routing = new class () extends AbstractExtension {
            public function getFunctions(): array
            {
                return [new TwigFunction(
                    'path',
                    fn (string $name, array $parameters = []): string => '/' . str_replace('_', '/', $name) . ($parameters === [] ? '' : '/' . implode('/', $parameters))
                )];
            }
        };

        return new AccountController(
            RendererFactory::create([
                'engines' => ['twig'],
                'extra' => false,
                'paths' => [
                    self::ROOT . '/resources/templates',
                    self::ROOT . '/tests/fixtures/templates',
                    self::ROOT . '/vendor/derafu/twig/resources/templates',
                ],
                'extensions' => [
                    $routing,
                    new TranslationExtension($translator, null, 'es'),
                    new AuthExtension(new WebConfiguration()),
                ],
            ]),
            $account ?? new BasicAccount()
        );
    }

    /**
     * @param array<string, mixed> $query
     */
    private function request(
        string $method = 'GET',
        string $path = '/auth/profile',
        ?UserInterface $user = null,
        array $query = [],
        ?SessionInterface $session = null,
        array $headers = []
    ): ServerRequestInterface {
        $request = (new ServerRequest([], [], 'https://app.test' . $path, $method, 'php://input', $headers))
            ->withQueryParams($query)
            ->withAttribute(MezzioUserInterface::class, $user ?? new User('ana', ['admin', 'editor'], ['name' => 'Ana Pérez', 'email' => 'ana@example.com', 'email_verified' => true, 'department' => 'Sales']))
            ->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, $session ?? new Session([]));

        return $request;
    }

    #[Test]
    public function theProfileShowsTheDataOfTheUser(): void
    {
        $html = $this->controller()->profile($this->request());

        $this->assertStringContainsString('Perfil', $html);
        $this->assertStringContainsString('ana', $html);
        $this->assertStringContainsString('Ana Pérez', $html);
        $this->assertStringContainsString('ana@example.com', $html);
        // The roles, one by one.
        $this->assertStringContainsString('admin', $html);
        $this->assertStringContainsString('editor', $html);
        // What the profile does not show of the details goes in the list of all of them.
        $this->assertStringContainsString('department', $html);
        $this->assertStringContainsString('Sales', $html);
    }

    #[Test]
    public function theProfileExplainsBasicAndOffersNoTokensWhenTheProviderHasNone(): void
    {
        $html = $this->controller()->profile($this->request());

        $this->assertStringContainsString('curl -u USERNAME:PASSWORD https://app.test/api/...', $html);
        $this->assertStringContainsString('/docs/api', $html);
        $this->assertStringNotContainsString('Generar un token', $html);
    }

    #[Test]
    public function theProfileShowsTheDataOfThePhpSession(): void
    {
        $html = $this->controller()->profile($this->request());

        $this->assertStringContainsString('Sesión de PHP', $html);
        $this->assertStringContainsString('Nombre de la sesión', $html);
        $this->assertStringContainsString('Cookie solo HTTP', $html);
    }

    #[Test]
    public function aTabCanBeOpenedByTheRequestAndAnUnknownOneIsTheFirst(): void
    {
        $controller = $this->controller();

        $this->assertMatchesRegularExpression(
            '/id="api-tab"[^>]*aria-selected="true"/',
            $controller->profile($this->request(query: ['tab' => 'api']))
        );
        $this->assertMatchesRegularExpression(
            '/id="data-tab"[^>]*aria-selected="true"/',
            $controller->profile($this->request(query: ['tab' => 'nonsense']))
        );
    }

    #[Test]
    public function nobodyThatIsNotAuthenticatedSeesTheProfile(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(401);

        $this->controller()->profile($this->request(user: new AnonymousUser()));
    }

    #[Test]
    public function aProviderWithoutTokensAnswersThatThereAreNone(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(404);

        $this->controller()->tokenCreate($this->request('POST', '/auth/profile/tokens'));
    }

    #[Test]
    public function whatChangesSomethingIsOnlyForTheSiteItself(): void
    {
        $this->expectException(AuthorizationException::class);

        $this->controller($this->accountWithTokens())->tokenCreate(
            $this->request('POST', '/auth/profile/tokens', headers: ['Sec-Fetch-Site' => 'cross-site'])
        );
    }

    #[Test]
    public function theTokensAreListedWithTheirData(): void
    {
        $html = $this->controller($this->accountWithTokens([
            new ApiToken('t1', 1_700_000_000, 1_700_100_000, 4_000_000_000, '203.0.113.9', 'Firefox'),
            new ApiToken('t2', 1_690_000_000, 1_690_000_100, 4_000_000_000),
        ]))->profile($this->request());

        $this->assertStringContainsString('Generar un token', $html);
        $this->assertStringContainsString('203.0.113.9', $html);
        $this->assertStringContainsString('Firefox', $html);
        // Each token is revoked by itself, one by one.
        $this->assertStringContainsString('action="/auth/token/revoke/t1"', $html);
        $this->assertStringContainsString('action="/auth/token/revoke/t2"', $html);
        $this->assertStringContainsString('curl -H "Authorization: Bearer TOKEN" https://app.test/api/...', $html);
    }

    #[Test]
    public function theProfileSaysWhyTheTokensAreNotThere(): void
    {
        $account = $this->accountWithTokens(failure: new AuthenticationException('Keycloak did not let the sessions be read (HTTP status 403).', 403));

        $html = $this->controller($account)->profile($this->request());

        $this->assertStringContainsString('Keycloak did not let the sessions be read', $html);
    }

    #[Test]
    public function aTokenIsMadeFromTheFormAndShownOnlyOnce(): void
    {
        $controller = $this->controller($this->accountWithTokens(created: 'the.offline.token'));

        $shown = $controller->tokenCreate($this->request('POST', '/auth/profile/tokens'));

        $this->assertInstanceOf(HtmlResponse::class, $shown);
        $this->assertStringContainsString('the.offline.token', (string) $shown->getBody());
        $this->assertSame('no-store', $shown->getHeaderLine('Cache-Control'));
    }

    #[Test]
    public function theFormAsksWhatTheProviderNeeds(): void
    {
        $html = $this->controller($this->accountWithTokens())->profile($this->request());

        $this->assertStringContainsString('name="password"', $html);
        $this->assertStringContainsString('action="/auth/token/create"', $html);
    }

    #[Test]
    public function aTokenThatCanNotBeMadeSendsTheUserBackWithTheReason(): void
    {
        $flash = $this->createMock(FlashMessagesInterface::class);
        $flash->expects($this->once())->method('flash')->with('error', $this->anything());
        $controller = $this->controller($this->accountWithTokens(
            failure: new AuthenticationException('The password is not valid.', 401),
            failOn: 'create'
        ));

        $response = $controller->tokenCreate(
            $this->request('POST', '/auth/profile/tokens')->withAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE, $flash)
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame('/auth/profile?tab=api', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function aTokenIsRevokedOneByOneAndTheUserGoesBackToItsTab(): void
    {
        $revoked = [];
        $flash = $this->createMock(FlashMessagesInterface::class);
        $flash->expects($this->once())->method('flash')->with('success', $this->anything());
        $controller = $this->controller($this->accountWithTokens(onRevoke: function (string $id) use (&$revoked): void {
            $revoked[] = $id;
        }));

        $response = $controller->tokenRevoke(
            $this->request('POST', '/auth/profile/tokens/t1/revoke')->withAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE, $flash),
            't1'
        );

        $this->assertSame(['t1'], $revoked);
        $this->assertSame('/auth/profile?tab=api', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function aTokenThatTheUserDoesNotHaveIsAnErrorForThePageNotAnException(): void
    {
        $flash = $this->createMock(FlashMessagesInterface::class);
        $flash->expects($this->once())->method('flash')->with('error', $this->anything());
        $controller = $this->controller($this->accountWithTokens(
            failure: new AuthenticationException('The user has no such token.', 404),
            failOn: 'revoke'
        ));

        $response = $controller->tokenRevoke(
            $this->request('POST', '/auth/profile/tokens/x/revoke')->withAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE, $flash),
            'x'
        );

        $this->assertSame('/auth/profile?tab=api', $response->getHeaderLine('Location'));
    }

    /**
     * An account like the one of Keycloak: it has tokens, and what it says is what
     * the test gives it.
     *
     * @param list<ApiToken> $tokens
     * @param \Closure(string): void|null $onRevoke What is done with the id of a token that is revoked.
     * @param 'list'|'create'|'revoke' $failOn What fails with `$failure`.
     */
    private function accountWithTokens(
        array $tokens = [],
        ?string $created = null,
        ?AuthenticationException $failure = null,
        string $failOn = 'list',
        ?\Closure $onRevoke = null
    ): AccountInterface {
        $manager = new class ($tokens, $created, $failure, $failOn, $onRevoke) implements ApiTokenManagerInterface {
            /**
             * @param list<ApiToken> $tokens
             */
            public function __construct(
                private readonly array $tokens,
                private readonly ?string $created,
                private readonly ?AuthenticationException $failure,
                private readonly string $failOn,
                private readonly ?\Closure $onRevoke
            ) {
            }

            public function list(SessionInterface $session): array
            {
                if ($this->failure !== null && $this->failOn === 'list') {
                    throw $this->failure;
                }

                return $this->tokens;
            }

            public function fields(): array
            {
                return [['name' => 'password', 'label' => 'Password', 'type' => 'password', 'required' => true]];
            }

            public function create(ServerRequestInterface $request, SessionInterface $session): string
            {
                if ($this->failure !== null && $this->failOn === 'create') {
                    throw $this->failure;
                }

                return $this->created ?? 'token';
            }

            public function revoke(SessionInterface $session, string $id): void
            {
                if ($this->failure !== null && $this->failOn === 'revoke') {
                    throw $this->failure;
                }

                if ($this->onRevoke !== null) {
                    ($this->onRevoke)($id);
                }
            }
        };

        return new class ($manager) extends BasicAccount {
            public function __construct(private readonly ApiTokenManagerInterface $manager)
            {
            }

            public function apiScheme(): string
            {
                return 'Bearer';
            }

            public function tokens(): ApiTokenManagerInterface
            {
                return $this->manager;
            }

            public function profile(UserInterface $user, SessionInterface $session): array
            {
                return [['label' => new TranslatableMessage('Language', [], 'auth'), 'value' => 'es']];
            }
        };
    }
}
