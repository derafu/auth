<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Keycloak;

use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakAccountClient;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The account API of Keycloak asks for roles of the client `account` that the token
 * of the session must have, and the client says which one is missing before it
 * asks Keycloak (which only answers with a 401 that does not say it).
 */
#[CoversClass(KeycloakAccountClient::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(TokenClaims::class)]
#[UsesClass(\Derafu\Auth\Account\ApiToken::class)]
#[UsesClass(AuthenticationException::class)]
final class KeycloakAccountClientTest extends TestCase
{
    /**
     * @var list<array{request: \Psr\Http\Message\RequestInterface}>
     */
    private array $requests = [];

    /**
     * @param list<Response> $answers
     */
    private function client(array $answers): KeycloakAccountClient
    {
        $stack = HandlerStack::create(new MockHandler($answers));
        $stack->push(Middleware::history($this->requests));

        return new KeycloakAccountClient(
            new KeycloakConfiguration([
                'keycloak_url' => 'https://keycloak.test',
                'realm' => 'test',
                'client_id' => 'my-site',
                'client_secret' => 'secret',
                'redirect_uri' => 'https://site.test/auth/callback',
            ]),
            new \GuzzleHttp\Client(['handler' => $stack])
        );
    }

    /**
     * An access token of the session, with the roles that the test says (the client
     * only reads what it says: Keycloak verified it when the user logged in).
     *
     * @param list<string>|null $roles The roles of the client `account`.
     */
    private function token(?array $roles): string
    {
        $claims = ['sub' => 'ana'] + ($roles !== null ? ['resource_access' => ['account' => ['roles' => $roles]]] : []);
        $encode = static fn (array $data): string => rtrim(strtr(base64_encode((string) json_encode($data)), '+/', '-_'), '=');

        return $encode(['alg' => 'RS256']) . '.' . $encode($claims) . '.signature';
    }

    /**
     * @return array<string, array{list<string>|null}>
     */
    public static function provideTokensWithoutViewProfile(): array
    {
        return [
            'without roles of the account' => [null],
            'with an empty list' => [[]],
            'only the role to revoke' => [['manage-account']],
            'roles that only look alike' => [['view-profile-extra', 'manage-account-links']],
        ];
    }

    /**
     * @param list<string>|null $roles
     */
    #[Test]
    #[DataProvider('provideTokensWithoutViewProfile')]
    public function theSessionsAreNotAskedWithoutTheRoleToReadThem(?array $roles): void
    {
        $client = $this->client([new Response(200, [], '[]')]);

        try {
            $client->tokens($this->token($roles));
            $this->fail('A token without view-profile must be refused.');
        } catch (AuthenticationException $e) {
            $this->assertSame(403, $e->getCode());
            $this->assertStringContainsString('view-profile', $e->getMessage());
            $this->assertStringContainsString('the client account', $e->getMessage());
            // Which application to fix is said too.
            $this->assertStringContainsString('my-site', $e->getMessage());
        }
        // Keycloak was not asked: its answer would not have said what is missing.
        $this->assertSame([], $this->requests);
    }

    #[Test]
    public function theSessionsAreAskedWithTheRoleToReadThem(): void
    {
        $client = $this->client([new Response(200, [], '[]'), new Response(200, [], '[]')]);

        $this->assertSame([], $client->tokens($this->token(['view-profile'])));
        $this->assertCount(2, $this->requests);
    }

    #[Test]
    public function aBrowserThatKeycloakDoesNotKnowIsNotShownAsOne(): void
    {
        $devices = [[
            'sessions' => [
                ['id' => 'a', 'started' => 100, 'lastAccess' => 200, 'expires' => 900, 'ipAddress' => '203.0.113.9', 'browser' => 'Other/Unknown', 'clients' => [['clientId' => 'my-site']]],
                ['id' => 'b', 'started' => 300, 'lastAccess' => 400, 'expires' => 900, 'ipAddress' => '203.0.113.10', 'browser' => 'Firefox/125.0', 'clients' => [['clientId' => 'my-site']]],
                ['id' => 'c', 'started' => 500, 'lastAccess' => 600, 'expires' => 900, 'clients' => [['clientId' => 'my-site']]],
            ],
        ]];
        $client = $this->client([new Response(200, [], '[]'), new Response(200, [], (string) json_encode($devices))]);

        $browsers = array_column(
            array_map(fn ($token) => ['id' => $token->id, 'browser' => $token->browser], $client->tokens($this->token(['view-profile']))),
            'browser',
            'id'
        );

        // The newest first.
        $this->assertSame(['c' => null, 'b' => 'Firefox/125.0', 'a' => null], $browsers);
    }

    #[Test]
    public function aTokenIsNotRevokedWithoutTheRoleToRevokeIt(): void
    {
        // The user can see its tokens (view-profile) and not revoke them.
        $client = $this->client([new Response(204)]);

        try {
            $client->revoke($this->token(['view-profile']), 'abc');
            $this->fail('A token without manage-account must be refused.');
        } catch (AuthenticationException $e) {
            $this->assertStringContainsString('manage-account', $e->getMessage());
            $this->assertStringContainsString('revoke', $e->getMessage());
        }
        $this->assertSame([], $this->requests);
    }

    #[Test]
    public function aTokenIsRevokedWithTheRoleToRevokeIt(): void
    {
        $client = $this->client([new Response(204)]);

        $client->revoke($this->token(['manage-account']), 'abc');

        $this->assertCount(1, $this->requests);
        $this->assertSame('DELETE', $this->requests[0]['request']->getMethod());
    }
}
