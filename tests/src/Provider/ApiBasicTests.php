<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider;

use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\LoginThrottle;
use Derafu\TestsAuth\Fixture\SessionApp;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * What a provider that has a password for each user does with a client of the
 * API that sends its user and its password (`Basic`): the same for every
 * provider, so the tests are written once.
 *
 * The class that uses it says how to make the authentication (with the users `ana`,
 * whose password is `secret`, as `identity()` says it) and gives its `SessionApp`.
 */
trait ApiBasicTests
{
    abstract protected function app(): SessionApp;

    /**
     * An authentication of the provider that protects `/api` and `/private`.
     *
     * @param array<string, mixed> $config What is added to the configuration.
     */
    abstract protected function basic(array $config = [], ?LoginThrottle $throttle = null): AuthenticationInterface;

    /**
     * The identity of a user whose password is `secret`.
     */
    abstract protected function identity(): string;

    /**
     * @param array<string, string> $headers
     * @return array{response: ResponseInterface, user: mixed}
     */
    private function call(
        AuthenticationInterface $authentication,
        array $headers = [],
        string $path = '/api/items',
        string $address = '203.0.113.7',
        ?string $network = null,
        ?string $sid = null
    ): array {
        $request = $this->app()->request($path, headers: $headers, address: $address, sid: $sid);
        if ($network !== null) {
            $request = $request->withAttribute('client_network', $network);
        }

        $user = null;
        $response = $this->app()->handleAuthenticated(
            $request,
            $authentication,
            function (ServerRequestInterface $request) use (&$user): null {
                $user = $request->getAttribute(MezzioUserInterface::class);

                return null;
            }
        );

        return ['response' => $response, 'user' => $user];
    }

    /**
     * @return array<string, string>
     */
    private function basicHeader(string $identity, string $password, string $scheme = 'Basic'): array
    {
        return ['Authorization' => $scheme . ' ' . base64_encode($identity . ':' . $password)];
    }

    #[Test]
    public function aClientThatSendsItsUserAndItsPasswordIsAuthenticated(): void
    {
        $result = $this->call($this->basic(), $this->basicHeader($this->identity(), 'secret'));

        $this->assertSame(200, $result['response']->getStatusCode());
        $this->assertInstanceOf(MezzioUserInterface::class, $result['user']);
        $this->assertSame($this->identity(), $result['user']->getIdentity());
    }

    #[Test]
    public function aClientOfTheApiDoesNotKeepASession(): void
    {
        $this->app()->persistence->store[SessionApp::KNOWN] = ['unrelated' => 'data'];
        $before = $this->app()->persistence->store;

        $this->call($this->basic(), $this->basicHeader($this->identity(), 'secret'));

        // Nothing was written: no user, no time of check, no session for the
        // client (so there is no cookie to set).
        $this->assertSame($before, $this->app()->persistence->store);
    }

    #[Test]
    public function aWrongPasswordGetsTheAnswerOfTheApiWithTheChallenge(): void
    {
        $result = $this->call($this->basic(), $this->basicHeader($this->identity(), 'wrong'));

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
        $this->assertSame('application/json', $result['response']->getHeaderLine('Content-Type'));
        $this->assertSame('Basic realm="API", charset="UTF-8"', $result['response']->getHeaderLine('WWW-Authenticate'));
        $this->assertSame(401, json_decode((string) $result['response']->getBody(), true)['status']);
    }

    #[Test]
    public function aUserThatDoesNotExistGetsTheSameAnswerAsAWrongPassword(): void
    {
        $wrong = $this->call($this->basic(), $this->basicHeader($this->identity(), 'wrong'))['response'];
        $unknown = $this->call($this->basic(), $this->basicHeader('nobody-at-all', 'secret'))['response'];

        $this->assertSame($wrong->getStatusCode(), $unknown->getStatusCode());
        $this->assertSame($wrong->getHeaders(), $unknown->getHeaders());
        $this->assertSame((string) $wrong->getBody(), (string) $unknown->getBody());
    }

    #[Test]
    public function aRequestWithoutCredentialsIsToldHowToAuthenticate(): void
    {
        $response = $this->call($this->basic())['response'];

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Basic realm="API", charset="UTF-8"', $response->getHeaderLine('WWW-Authenticate'));
    }

    #[Test]
    public function aScriptOfAPageGetsThe401WithoutTheChallengeThatOpensTheWindowOfTheBrowser(): void
    {
        foreach (['XMLHttpRequest', 'xmlhttprequest'] as $value) {
            $response = $this->call($this->basic(), ['X-Requested-With' => $value])['response'];

            $this->assertSame(401, $response->getStatusCode());
            $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
            $this->assertFalse($response->hasHeader('WWW-Authenticate'));
        }

        // With credentials that are wrong it is the same.
        $response = $this->call(
            $this->basic(),
            ['X-Requested-With' => 'XMLHttpRequest'] + $this->basicHeader($this->identity(), 'wrong')
        )['response'];
        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($response->hasHeader('WWW-Authenticate'));
    }

    #[Test]
    public function anotherValueOfTheHeaderOfTheScriptsKeepsTheChallenge(): void
    {
        $response = $this->call($this->basic(), ['X-Requested-With' => 'com.example.app'])['response'];

        $this->assertSame('Basic realm="API", charset="UTF-8"', $response->getHeaderLine('WWW-Authenticate'));
    }

    #[Test]
    public function theSchemeDoesNotDependOnItsCase(): void
    {
        foreach (['Basic', 'basic', 'BASIC', 'bAsIc'] as $scheme) {
            $result = $this->call($this->basic(), $this->basicHeader($this->identity(), 'secret', $scheme));

            $this->assertSame($this->identity(), $result['user']?->getIdentity(), $scheme);
        }
    }

    #[Test]
    public function aPasswordCanHaveColonsAndSpacesAndUnicode(): void
    {
        $authentication = $this->basic();

        // Only the first colon separates: what follows is the password. The
        // password that these users have is "secret", so they do not get in, but
        // they are read whole (a password that was cut would be a different one).
        foreach (['se:cret', 'sec ret', 'séc:rét ñ'] as $password) {
            $this->assertNull($this->call($authentication, $this->basicHeader($this->identity(), $password))['user'], $password);
        }
        $this->assertSame($this->identity(), $this->call($authentication, $this->basicHeader($this->identity(), 'secret'))['user']?->getIdentity());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function provideCredentialsThatAreNotValid(): array
    {
        return [
            'not base64' => ['Basic !!!not-base64!!!'],
            'base64 with spaces inside' => ['Basic YW5h OnNlY3JldA=='],
            'no colon' => ['Basic ' . 'YW5hc2VjcmV0'],
            'an empty identity' => ['Basic ' . 'OnNlY3JldA=='],
            'not utf-8' => ['Basic ' . 'gP86c2VjcmV0'],
            'nothing after the scheme' => ['Basic'],
            'only the scheme and a space' => ['Basic '],
            'two schemes' => ['Basic YW5hOnNlY3JldA==, Bearer abc'],
            'a word that is not credentials' => ['Basic one two'],
            'empty' => [''],
        ];
    }

    #[Test]
    #[DataProvider('provideCredentialsThatAreNotValid')]
    public function credentialsThatAreNotValidDoNotAuthenticate(string $header): void
    {
        $result = $this->call($this->basic(), ['Authorization' => $header]);

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
    }

    #[Test]
    public function aHeaderOfAnotherSchemeIsNotCredentialsForThisProvider(): void
    {
        $result = $this->call($this->basic(), ['Authorization' => 'Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig']);

        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
        $this->assertSame('Basic realm="API", charset="UTF-8"', $result['response']->getHeaderLine('WWW-Authenticate'));
    }

    // -------------------------------------------------------------------------
    // Only in the API, and never instead of a session that is not asked.
    // -------------------------------------------------------------------------

    #[Test]
    public function theCredentialsAreOnlyReadInTheApi(): void
    {
        // The same valid credentials in a page: they are not read, the user is
        // the one of the session (there is none) and the path is protected.
        $result = $this->call($this->basic(), $this->basicHeader($this->identity(), 'secret'), '/private/page');

        $this->assertNull($result['user']);
        $this->assertSame(302, $result['response']->getStatusCode());
    }

    #[Test]
    public function aHeaderThatAServerInFrontAddsDoesNotBreakTheSessionOfAPage(): void
    {
        // The whole site is behind a `Basic` of the web server, whose user is not a
        // user of the application: the session of the user must go on.
        $this->app()->persistence->store['logged'] = [
            'user' => ['identity' => $this->identity()],
            'auth_checked_at' => time(),
        ];

        $result = $this->call(
            $this->basic(),
            $this->basicHeader('web-server-user', 'its-password'),
            '/private/page',
            sid: 'logged'
        );

        $this->assertSame($this->identity(), $result['user']?->getIdentity());
    }

    #[Test]
    public function aClientOfTheApiThatSendsBadCredentialsDoesNotGoBackToItsSession(): void
    {
        $this->app()->persistence->store['logged'] = [
            'user' => ['identity' => $this->identity()],
            'auth_checked_at' => time(),
        ];

        // Without credentials the session is the user (a browser that calls the
        // API); with credentials that are not valid, it is not.
        $this->assertSame($this->identity(), $this->call($this->basic(), [], sid: 'logged')['user']?->getIdentity());

        $result = $this->call($this->basic(), $this->basicHeader($this->identity(), 'wrong'), sid: 'logged');
        $this->assertNull($result['user']);
        $this->assertSame(401, $result['response']->getStatusCode());
    }

    #[Test]
    public function theCredentialsOfAnotherUserAreNotTheOnesOfTheSession(): void
    {
        $this->app()->persistence->store['logged'] = [
            'user' => ['identity' => 'someone-else'],
            'auth_checked_at' => time(),
        ];

        $result = $this->call($this->basic(), $this->basicHeader($this->identity(), 'secret'), sid: 'logged');

        // The one that the credentials say, not the one of the session.
        $this->assertSame($this->identity(), $result['user']?->getIdentity());
    }

    #[Test]
    public function theRealmAndThePathOfTheApiAreConfigurable(): void
    {
        $authentication = $this->basic(['api_realm' => 'Billing', 'api_paths' => ['/v1'], 'protected_paths' => ['/v1', '/api']]);

        $challenge = $this->call($authentication, [], '/v1/invoices')['response']->getHeaderLine('WWW-Authenticate');
        $this->assertSame('Basic realm="Billing", charset="UTF-8"', $challenge);

        $result = $this->call($authentication, $this->basicHeader($this->identity(), 'secret'), '/v1/invoices');
        $this->assertSame($this->identity(), $result['user']?->getIdentity());

        // /api is protected but it is a page now: the credentials are not read there.
        $this->assertNull($this->call($authentication, $this->basicHeader($this->identity(), 'secret'), '/api/items')['user']);
    }

    #[Test]
    public function thereCanBeSeveralPathsOfTheApiAndTheyAreNotOnlyUnderApi(): void
    {
        $authentication = $this->basic([
            'api_paths' => ['/api', '/docs/index.json', '/v2'],
            'protected_paths' => ['/api', '/docs', '/v2'],
        ]);
        $credentials = $this->basicHeader($this->identity(), 'secret');

        // Each one is the path of an API, and what is below it. They are read by
        // segments: /v2 is not /v2beta.
        foreach (['/api/items', '/docs/index.json', '/docs/index.json/x', '/v2', '/v2/items'] as $path) {
            $this->assertSame($this->identity(), $this->call($authentication, $credentials, $path)['user']?->getIdentity(), $path);
            $this->assertSame(
                'Basic realm="API", charset="UTF-8"',
                $this->call($authentication, [], $path)['response']->getHeaderLine('WWW-Authenticate'),
                $path
            );
        }

        // A page that is protected and is not one of the API: a session, and a
        // redirect, never the credentials of the header.
        foreach (['/docs/other', '/docs'] as $path) {
            $result = $this->call($authentication, $credentials, $path);

            $this->assertNull($result['user'], $path);
            $this->assertSame(302, $result['response']->getStatusCode(), $path);
        }

        // /v2beta is neither: it is public, and the credentials are not read there.
        $this->assertTrue($this->call($authentication, $credentials, '/v2beta')['user']?->isAnonymous());
    }

    #[Test]
    public function theCredentialsAreReadWhateverWayThePathOfTheApiIsWritten(): void
    {
        $authentication = $this->basic();

        // The pipeline gives the canonical path, but this does not depend on it.
        foreach (['/api', '/api/', '/api//items', '/api/./items', '/api/%69tems'] as $path) {
            $result = $this->call($authentication, $this->basicHeader($this->identity(), 'secret'), $path);

            $this->assertSame($this->identity(), $result['user']?->getIdentity(), $path);
        }
    }

    // -------------------------------------------------------------------------
    // Failed attempts.
    // -------------------------------------------------------------------------

    #[Test]
    public function theFailedAttemptsAreLimitedAsTheOnesOfTheLoginFormAre(): void
    {
        $authentication = $this->basic(throttle: new LoginThrottle(new ArrayAdapter(), maxAttempts: 2, lockSeconds: 600));
        $wrong = $this->basicHeader($this->identity(), 'wrong');

        $this->call($authentication, $wrong);
        $this->call($authentication, $wrong);

        // Limited: not even the right password is checked.
        $this->assertNull($this->call($authentication, $this->basicHeader($this->identity(), 'secret'))['user']);
        // Another client is not.
        $other = $this->call($authentication, $this->basicHeader($this->identity(), 'secret'), address: '198.51.100.9');
        $this->assertSame($this->identity(), $other['user']?->getIdentity());
    }

    #[Test]
    public function theLimitCountsByTheNetworkOfTheClientNotByTheHeaders(): void
    {
        $authentication = $this->basic(throttle: new LoginThrottle(new ArrayAdapter(), maxAttempts: 2, lockSeconds: 600));

        // A different address in each request is still the same client.
        foreach (['198.51.100.1', '198.51.100.2'] as $forged) {
            $this->call($authentication, $this->basicHeader($this->identity(), 'wrong') + ['X-Forwarded-For' => $forged]);
        }
        $blocked = $this->call($authentication, $this->basicHeader($this->identity(), 'secret') + ['X-Forwarded-For' => '198.51.100.99']);
        $this->assertNull($blocked['user']);

        // And the network that the HTTP layer decided is what tells clients apart.
        $this->call($authentication, $this->basicHeader($this->identity(), 'wrong'), address: '10.0.0.1', network: '203.0.113.9/32');
        $this->call($authentication, $this->basicHeader($this->identity(), 'wrong'), address: '10.0.0.1', network: '203.0.113.9/32');
        $this->assertNull($this->call($authentication, $this->basicHeader($this->identity(), 'secret'), address: '10.0.0.2', network: '203.0.113.9/32')['user']);
        $this->assertSame(
            $this->identity(),
            $this->call($authentication, $this->basicHeader($this->identity(), 'secret'), address: '10.0.0.1', network: '203.0.113.10/32')['user']?->getIdentity()
        );
    }

    #[Test]
    public function aSuccessfulAttemptClearsTheFailedOnes(): void
    {
        $throttle = new LoginThrottle(new ArrayAdapter(), maxAttempts: 2, lockSeconds: 600);
        $authentication = $this->basic(throttle: $throttle);

        $this->call($authentication, $this->basicHeader($this->identity(), 'wrong'));
        $this->call($authentication, $this->basicHeader($this->identity(), 'secret'));
        $this->call($authentication, $this->basicHeader($this->identity(), 'wrong'));

        // One failed attempt after the right one, not two.
        $this->assertFalse($throttle->isLimited($this->identity(), '203.0.113.7'));
    }
}
