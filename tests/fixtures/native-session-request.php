<?php

declare(strict_types=1);

/**
 * One request of the application, in its own process and with the native
 * sessions of PHP (the persistence of Mezzio that applications use), for the
 * tests that need two requests at the same time.
 *
 * The parameters are in the environment: SESSION_PATH, SESSION_ID, MODE,
 * TEST_KEYCLOAK_URL and GO_FILE.
 *
 *   - `seed`: writes the data of the session (JSON, from the standard input).
 *   - `request`: waits until GO_FILE exists (so two processes start together),
 *     asks for a protected page with the session and says what happened.
 *   - `dump`: says what the session has (JSON).
 */

use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\TestsAuth\Fixture\Stack;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use Mezzio\Session\Ext\PhpSessionPersistence;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

ini_set('session.save_path', (string) getenv('SESSION_PATH'));
ini_set('session.name', 'sid');
ini_set('session.use_cookies', '0');
ini_set('session.cache_limiter', '');

$id = (string) getenv('SESSION_ID');
$mode = (string) getenv('MODE');

if ($mode === 'seed' || $mode === 'dump') {
    session_id($id);
    session_start();
    if ($mode === 'seed') {
        $_SESSION = json_decode((string) stream_get_contents(STDIN), true);
        echo '{}';
    } else {
        echo json_encode($_SESSION);
    }
    session_write_close();

    return;
}

$config = Stack::keycloakConfiguration([
    'keycloak_url' => (string) getenv('TEST_KEYCLOAK_URL'),
    'realm' => 'test',
    'client_id' => 'derafu-auth',
    'client_secret' => 'test-secret',
    'redirect_uri' => 'https://app.test/auth/callback',
    'enabled' => true,
    'protected_paths' => ['/private'],
    'refresh_interval' => 600,
]);
$authentication = Stack::keycloak(
    new KeycloakUserRepository($config),
    $config,
    new KeycloakSessionManager()
);

while (!file_exists((string) getenv('GO_FILE'))) {
    usleep(500);
}

$result = new ArrayObject();
$handler = new class ($authentication, $result) implements RequestHandlerInterface {
    public function __construct(
        private readonly AuthenticationInterface $authentication,
        private readonly ArrayObject $result
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $user = $this->authentication->authenticate($request);
        $this->result->exchangeArray([
            'authenticated' => $user !== null && !$user->isAnonymous(),
            'roles' => $user === null ? [] : iterator_to_array($user->getRoles()),
        ]);

        return new Response();
    }
};

(new SessionMiddleware(new PhpSessionPersistence()))->process(
    (new ServerRequest())
        ->withUri(new Uri('https://app.test/private/page'))
        ->withMethod('GET')
        ->withCookieParams(['sid' => $id]),
    $handler
);

echo json_encode($result->getArrayCopy());
