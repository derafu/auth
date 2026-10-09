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
use Derafu\Auth\Authentication\Channel\Web\SessionManager;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakController;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Auth\User;
use Derafu\TestsAuth\Fixture\KeycloakBrowser;
use Derafu\TestsAuth\Fixture\RealKeycloak;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Fixture\Stack;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Two requests of the same session that need to renew the token at the same time,
 * when Keycloak lets a refresh token be used only once (the realm revokes the
 * one that was used and gives a new one).
 *
 * Each request is a process of its own, with the native sessions of PHP and the
 * persistence of Mezzio that applications use, against a real Keycloak. With the
 * sessions as they are by default PHP locks the session while a request has it,
 * so the second request waits and finds the tokens that the first one saved: the
 * user is not logged out.
 *
 * This is why the sessions must be the locking ones (the default of PHP and of
 * Mezzio) when the realm renews the refresh tokens: without the lock both
 * requests read the same refresh token, the second one is refused, and what
 * happens to the session depends on which request saves last.
 */
#[CoversClass(KeycloakWebFlow::class)]
#[UsesClass(KeycloakUserRepository::class)]
#[UsesClass(KeycloakSessionManager::class)]
#[UsesClass(\Derafu\Auth\Authentication\AuthenticationManager::class)]
#[UsesClass(\Derafu\Auth\Authentication\Identification::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\WebConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Web\Flash::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiChannel::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\ApiConfiguration::class)]
#[UsesClass(\Derafu\Auth\Authorization\AccessRules::class)]
#[UsesClass(\Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\Api\KeycloakBearerScheme::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(KeycloakController::class)]
#[UsesClass(KeycloakTokenVerifier::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
#[UsesClass(SessionManager::class)]
#[UsesClass(User::class)]
#[UsesClass(AuthTranslationResourceProvider::class)]
final class KeycloakConcurrentRefreshTest extends TestCase
{
    private static RealKeycloak $keycloak;

    private string $directory;

    public static function setUpBeforeClass(): void
    {
        self::$keycloak = RealKeycloak::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$keycloak->stop();
    }

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/' . uniqid('derafu_auth_sessions_');
        mkdir($this->directory);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->directory);
        self::$keycloak->admin()->reset();
    }

    /**
     * The login of `ana` in the application, and the data of its session.
     *
     * @return array{array<string, mixed>, KeycloakUserRepository}
     */
    private function logIn(): array
    {
        $app = new SessionApp();
        $config = Stack::keycloakConfiguration([
            'keycloak_url' => self::$keycloak->url(),
            'realm' => 'test',
            'client_id' => 'derafu-auth',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.test/auth/callback',
            'enabled' => true,
            'protected_paths' => ['/private'],
        ]);
        $sessionManager = new KeycloakSessionManager();
        $repository = new KeycloakUserRepository($config);
        $authentication = Stack::keycloak($repository, $config, $sessionManager);
        $controller = new KeycloakController(Stack::webOf($config), $sessionManager);

        $page = $app->handleAuthenticated($app->request('/private/page'), $authentication, fn (): null => null);
        $query = (new KeycloakBrowser())->logIn($page->getHeaderLine('Location'));
        $response = $app->handleAuthenticated(
            $app->request('/auth/callback', $query),
            $authentication,
            fn (ServerRequestInterface $request) => $controller->handle($request)
        );

        return [$app->persistence->store[$app->sessionId($response)], $repository];
    }

    /**
     * Starts the script of a request in its own process.
     *
     * @param array<string, string> $environment
     * @return array{resource, array<int, resource>}
     */
    private function start(string $mode, string $id, array $environment = []): array
    {
        $process = proc_open(
            [PHP_BINARY, dirname(__DIR__, 3) . '/fixtures/native-session-request.php'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            [
                'MODE' => $mode,
                'SESSION_ID' => $id,
                'SESSION_PATH' => $this->directory,
                'TEST_KEYCLOAK_URL' => self::$keycloak->url(),
                'GO_FILE' => $this->directory . '/go',
                'PATH' => (string) getenv('PATH'),
            ] + $environment
        );
        $this->assertIsResource($process);

        return [$process, $pipes];
    }

    /**
     * Waits for the process and gives what it said.
     *
     * @param array{resource, array<int, resource>} $started
     * @return array<string, mixed>
     */
    private function finish(array $started, ?string $input = null): array
    {
        [$process, $pipes] = $started;
        if ($input !== null) {
            fwrite($pipes[0], $input);
        }
        fclose($pipes[0]);
        $output = (string) stream_get_contents($pipes[1]);
        $errors = (string) stream_get_contents($pipes[2]);
        proc_close($process);

        $decoded = json_decode($output, true);
        $this->assertIsArray($decoded, 'The script said: ' . $output . $errors);

        return $decoded;
    }

    /**
     * What the session has now.
     *
     * @return array<string, mixed>
     */
    private function session(string $id): array
    {
        return $this->finish($this->start('dump', $id));
    }

    /**
     * Two requests that arrive together to a session whose user is due to be
     * asked again.
     *
     * @return array{list<array<string, mixed>>, array<string, mixed>, array<string, mixed>}
     * What each request got, the session before and the session after.
     */
    private function twoRequests(): array
    {
        self::$keycloak->admin()->setRevokeRefreshToken(true);
        [$data] = $this->logIn();
        $data['auth_checked_at'] = time() - 601;
        $id = bin2hex(random_bytes(16));

        $seed = $this->start('seed', $id);
        $this->finish($seed, (string) json_encode($data));

        $first = $this->start('request', $id);
        $second = $this->start('request', $id);
        usleep(1_500_000);
        file_put_contents($this->directory . '/go', '');

        return [[$this->finish($first), $this->finish($second)], $data, $this->session($id)];
    }

    #[Test]
    public function twoRequestsThatRenewTheTokenTogetherDoNotLogTheUserOutWithTheLockingSessions(): void
    {
        [$results, $before, $after] = $this->twoRequests();

        // Both got the user, with its roles.
        foreach ($results as $result) {
            $this->assertTrue($result['authenticated']);
            $this->assertContains('admin', $result['roles']);
        }

        // The session kept the user and has the refresh token that Keycloak gave
        // in exchange of the one that it had, which is now revoked: the first
        // request renewed it, the second one did not need to.
        $this->assertSame($before['user']['sub'], $after['user']['sub']);
        $this->assertNotSame($before['oauth2_refresh_token'], $after['oauth2_refresh_token']);
        $this->assertGreaterThan($before['auth_checked_at'], $after['auth_checked_at']);

        [, $repository] = $this->logIn();
        try {
            $repository->refreshToken($before['oauth2_refresh_token']);
            $this->fail('The refresh token that was used should be revoked: the realm did not renew it.');
        } catch (AuthenticationException $e) {
            $this->assertStringStartsWith('Failed to refresh token: ', $e->getMessage());
        }
    }
}
