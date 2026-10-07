<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Keycloak;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\KeycloakAuthentication;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakController;
use Derafu\Auth\Provider\Keycloak\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUser;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\SessionManager;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\User;
use Derafu\TestsAuth\Fixture\KeycloakBrowser;
use Derafu\TestsAuth\Fixture\RealKeycloak;
use Derafu\TestsAuth\Fixture\SessionApp;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What a session knows about its user is a copy, and this is when it stops being
 * true: the application asks Keycloak again when the token expires or, if it is
 * before, every `refresh_interval` seconds (what happens first).
 *
 * Everything is against a real Keycloak (see `RealKeycloak`), and what the
 * administrator of the realm does while the user has a session (takes a role
 * away, disables the user, ends its sessions) is done through the REST API of
 * Keycloak, as a person would.
 */
#[CoversClass(KeycloakAuthentication::class)]
#[CoversClass(KeycloakUserRepository::class)]
#[CoversClass(KeycloakSessionManager::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(KeycloakController::class)]
#[UsesClass(KeycloakTokenVerifier::class)]
#[UsesClass(KeycloakUser::class)]
#[UsesClass(SessionManager::class)]
#[UsesClass(User::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class KeycloakRefreshTest extends TestCase
{
    private static RealKeycloak $keycloak;

    private SessionApp $app;

    private KeycloakBrowser $browser;

    public static function setUpBeforeClass(): void
    {
        self::$keycloak = RealKeycloak::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$keycloak->unpause();
        self::$keycloak->stop();
    }

    protected function setUp(): void
    {
        $this->app = new SessionApp();
        $this->browser = new KeycloakBrowser();
    }

    protected function tearDown(): void
    {
        self::$keycloak->unpause();
        self::$keycloak->admin()->reset();
    }

    /**
     * @param array<string, mixed> $config
     * @return array{KeycloakAuthentication, KeycloakController}
     */
    private function keycloak(array $config = []): array
    {
        $config = new KeycloakConfiguration($config + [
            'keycloak_url' => self::$keycloak->url(),
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'enabled' => true,
            'protected_paths' => ['/private'],
        ]);
        $sessionManager = new KeycloakSessionManager();

        return [
            new KeycloakAuthentication(new KeycloakUserRepository($config), $config, $sessionManager),
            new KeycloakController($config, $sessionManager),
        ];
    }

    /**
     * The whole login of `ana`: the page, Keycloak and the callback. It gives the
     * identifier of the session.
     *
     * @param array{KeycloakAuthentication, KeycloakController} $keycloak
     */
    private function logIn(array $keycloak): string
    {
        [$authentication, $controller] = $keycloak;

        $response = $this->app->handleAuthenticated(
            $this->app->request('/private/page'),
            $authentication,
            function (): void {
                $this->fail('The user is not logged in.');
            }
        );
        $query = $this->browser->logIn($response->getHeaderLine('Location'));

        $response = $this->app->handleAuthenticated(
            $this->app->request('/auth/callback', $query),
            $authentication,
            fn (ServerRequestInterface $request) => $controller->handle($request)
        );

        return $this->app->sessionId($response);
    }

    /**
     * The user asks for a protected page with the session.
     *
     * @phpstan-impure
     * @return array{ResponseInterface, MezzioUserInterface|null} The response
     * and the user that the page got (null if it did not get to run).
     */
    private function visit(KeycloakAuthentication $authentication, string $sid): array
    {
        $user = null;
        $response = $this->app->handleAuthenticated(
            $this->app->request('/private/page', sid: $sid),
            $authentication,
            function (ServerRequestInterface $request) use (&$user): void {
                $user = $request->getAttribute(MezzioUserInterface::class);
            }
        );

        return [$response, $user];
    }

    /**
     * @return list<string>
     */
    private function roles(?MezzioUserInterface $user): array
    {
        $this->assertNotNull($user, 'The page did not run: the user has no session.');
        $roles = iterator_to_array($user->getRoles());
        sort($roles);

        return $roles;
    }

    #[Test]
    public function aRoleThatIsTakenAwayIsSeenWhenTheTokenExpires(): void
    {
        $admin = self::$keycloak->admin();
        $admin->setAccessTokenLifespan(6);
        [$authentication] = $keycloak = $this->keycloak();
        $sid = $this->logIn($keycloak);
        $this->assertSame(['admin', 'app-editor'], $this->roles($this->visit($authentication, $sid)[1]));

        $admin->removeRealmRole('ana', 'admin');
        $admin->addRealmRole('ana', 'editor');

        // The token has not expired: the session still has the roles that it was
        // given, so what Keycloak says now is not seen yet.
        $this->assertSame(['admin', 'app-editor'], $this->roles($this->visit($authentication, $sid)[1]));

        sleep(7);

        // It expired: the session is renewed with the token that Keycloak gives
        // now, and the roles are the ones of now.
        $before = $this->app->persistence->store[$sid]['oauth2_token'];
        $this->assertSame(['app-editor', 'editor'], $this->roles($this->visit($authentication, $sid)[1]));
        $this->assertNotSame($before, $this->app->persistence->store[$sid]['oauth2_token']);
    }

    #[Test]
    public function theIntervalAsksKeycloakBeforeTheTokenExpires(): void
    {
        $admin = self::$keycloak->admin();
        [$authentication] = $keycloak = $this->keycloak(['refresh_interval' => 2]);
        $sid = $this->logIn($keycloak);
        $admin->removeRealmRole('ana', 'admin');
        $admin->addRealmRole('ana', 'editor');

        $this->assertSame(['admin', 'app-editor'], $this->roles($this->visit($authentication, $sid)[1]));

        sleep(3);

        $this->assertSame(['app-editor', 'editor'], $this->roles($this->visit($authentication, $sid)[1]));
        // The token had minutes to go: it was the interval and not the token.
        $this->assertGreaterThan(time() + 200, $this->app->persistence->store[$sid]['oauth2_expiry']);
    }

    #[Test]
    public function aSessionThatWasJustCheckedIsNotAskedAgainBeforeTheInterval(): void
    {
        $admin = self::$keycloak->admin();
        [$authentication] = $keycloak = $this->keycloak(['refresh_interval' => 600]);
        $sid = $this->logIn($keycloak);
        $token = $this->app->persistence->store[$sid]['oauth2_token'];
        $admin->removeRealmRole('ana', 'admin');

        $this->assertSame(['admin', 'app-editor'], $this->roles($this->visit($authentication, $sid)[1]));
        $this->assertSame($token, $this->app->persistence->store[$sid]['oauth2_token']);
    }

    #[Test]
    public function aUserThatKeycloakDisabledLosesTheSession(): void
    {
        [$authentication] = $keycloak = $this->keycloak(['refresh_interval' => 600]);
        $sid = $this->logIn($keycloak);
        self::$keycloak->admin()->setEnabled('ana', false);
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 601;

        [$response, $user] = $this->visit($authentication, $sid);

        $this->assertNull($user);
        $this->assertStringStartsWith(self::$keycloak->url(), $response->getHeaderLine('Location'));
        foreach (['user', 'oauth2_token', 'oauth2_refresh_token', 'auth_checked_at'] as $key) {
            $this->assertArrayNotHasKey($key, $this->app->persistence->store[$sid]);
        }
    }

    #[Test]
    public function aSessionThatTheAdministratorEndedInKeycloakIsClosed(): void
    {
        [$authentication] = $keycloak = $this->keycloak(['refresh_interval' => 600]);
        $sid = $this->logIn($keycloak);
        self::$keycloak->admin()->logOut('ana');
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 601;

        [$response, $user] = $this->visit($authentication, $sid);

        $this->assertNull($user);
        $this->assertStringStartsWith(self::$keycloak->url(), $response->getHeaderLine('Location'));
        $this->assertArrayNotHasKey('user', $this->app->persistence->store[$sid]);
        $this->assertArrayNotHasKey('oauth2_refresh_token', $this->app->persistence->store[$sid]);
    }

    #[Test]
    public function aKeycloakThatDoesNotAnswerDoesNotCloseTheSessionsAndTheNextRequestContinuesIt(): void
    {
        [$authentication] = $keycloak = $this->keycloak([
            'refresh_interval' => 600,
            'http_client_options' => ['timeout' => 2, 'connect_timeout' => 2],
        ]);
        $sid = $this->logIn($keycloak);
        $session = $this->app->persistence->store[$sid];
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 601;

        self::$keycloak->pause();
        [$response, $user] = $this->visit($authentication, $sid);
        self::$keycloak->unpause();

        // The user can not be verified, so the page does not run (nobody is let in
        // without being verified), but the session is the same: nothing that it
        // had was thrown away.
        $this->assertNull($user);
        $this->assertInstanceOf(RedirectResponse::class, $response);
        foreach (['user', 'oauth2_token', 'oauth2_refresh_token', 'oauth2_id_token', 'oauth2_expiry'] as $key) {
            $this->assertSame($session[$key], $this->app->persistence->store[$sid][$key], $key);
        }

        // Keycloak is back: the same session goes on, without logging in again.
        sleep(1);
        [, $user] = $this->visit($authentication, $sid);
        $this->assertSame(['admin', 'app-editor'], $this->roles($user));
        $this->assertNotSame($session['oauth2_token'], $this->app->persistence->store[$sid]['oauth2_token']);
    }

    #[Test]
    public function aRefusalThatIsNotOfTheTokenDoesNotCloseTheSessionEither(): void
    {
        $sid = $this->logIn($this->keycloak(['refresh_interval' => 600]));
        $session = $this->app->persistence->store[$sid];
        $this->app->persistence->store[$sid]['auth_checked_at'] = time() - 601;

        // The application has a secret that Keycloak does not know (it was
        // changed): every refresh is refused, but not because of the session.
        [$authentication] = $this->keycloak(['refresh_interval' => 600, 'client_secret' => 'a-secret-that-is-not-it']);
        [$response, $user] = $this->visit($authentication, $sid);

        $this->assertNull($user);
        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame($session['oauth2_refresh_token'], $this->app->persistence->store[$sid]['oauth2_refresh_token']);
        $this->assertSame($session['user'], $this->app->persistence->store[$sid]['user']);
    }
}
