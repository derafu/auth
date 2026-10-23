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

use Closure;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakAccountClient;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use Exception;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * The account API of Keycloak asks for roles of the client `account` that the token
 * of the session must have, and the client says which one is missing before it
 * asks Keycloak (which only answers with a 401 that does not say it).
 */
#[CoversClass(KeycloakAccountClient::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(TokenClaims::class)]
#[CoversClass(\Derafu\Auth\Account\ApiToken::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(ProviderUnavailableException::class)]
final class KeycloakAccountClientTest extends TestCase
{
    /**
     * @var list<array{request: RequestInterface}>
     */
    private array $requests = [];

    /**
     * @param list<Response|Exception> $answers
     */
    private function client(array $answers): KeycloakAccountClient
    {
        $stack = HandlerStack::create(new MockHandler($answers));
        $stack->push(Middleware::mapRequest(function (RequestInterface $request): RequestInterface {
            $this->requests[] = ['request' => $request];
            return $request;
        }));

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

    /** @param Closure(): mixed $read */
    private function assertInvalidResponse(Closure $read, string $field): void
    {
        try {
            $read();
            $this->fail('The malformed response must be rejected.');
        } catch (AuthenticationException $e) {
            $this->assertSame(400, $e->getCode());
            $this->assertInstanceOf(TranslatableInvalidArgumentException::class, $e->getPrevious());
            $this->assertStringContainsString('Invalid response from the Keycloak account API:', $e->getMessage());
            $this->assertStringContainsString($field, $e->getPrevious()->getMessage());
        }
    }

    /** @return iterable<string, array{mixed}> */
    public static function malformedBodies(): iterable
    {
        yield 'null' => [null];
        yield 'string' => ['invalid'];
        yield 'boolean' => [false];
        yield 'number' => [1];
        yield 'scalar record' => [[1]];
        yield 'null record' => [[null]];
        yield 'list record' => [[['invalid']]];
        yield 'numeric field name' => [[['id' => 'session', 7 => 'invalid']]];
    }

    #[DataProvider('malformedBodies')]
    public function testMalformedResponseRecordsKeepTheReaderExceptionAsTheirCause(mixed $body): void
    {
        $client = $this->client([new Response(200, [], json_encode($body, JSON_THROW_ON_ERROR))]);
        $this->assertInvalidResponse(fn () => $client->session($this->token(['view-profile']), 'session'), 'Keycloak account API');
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function invalidSessionFields(): iterable
    {
        foreach (['id', 'ipAddress', 'browser'] as $field) {
            foreach (['integer' => 1, 'boolean' => false, 'float' => 1.5, 'array' => []] as $type => $value) {
                yield $field . ' as ' . $type => [[$field => $value], $field];
            }
        }
        foreach (['started', 'lastAccess', 'expires'] as $field) {
            foreach (['numeric string' => '100', 'boolean' => false, 'float' => 1.5, 'array' => []] as $type => $value) {
                yield $field . ' as ' . $type => [[$field => $value], $field];
            }
        }
        yield 'clients as string' => [['clients' => 'my-site'], 'clients'];
        yield 'client as scalar' => [['clients' => ['my-site']], 'clients'];
    }

    /** @param array<string, mixed> $fields */
    #[DataProvider('invalidSessionFields')]
    public function testRejectsInvalidTypesInOfflineSessions(array $fields, string $field): void
    {
        $session = array_replace(['id' => 'offline', 'clients' => [['clientId' => 'my-site']]], $fields);
        $client = $this->client([
            new Response(200, [], '[]'),
            new Response(200, [], json_encode([['sessions' => [$session]]], JSON_THROW_ON_ERROR)),
        ]);

        $this->assertInvalidResponse(fn () => $client->tokens($this->token(['view-profile'])), $field);
    }

    /** @return iterable<string, array{mixed}> */
    public static function malformedNestedSessions(): iterable
    {
        yield 'string collection' => ['invalid'];
        yield 'boolean collection' => [false];
        yield 'scalar session' => [[1]];
        yield 'null session' => [[null]];
        yield 'list session' => [[['invalid']]];
    }

    #[DataProvider('malformedNestedSessions')]
    public function testRejectsMalformedNestedSessionCollections(mixed $sessions): void
    {
        $client = $this->client([
            new Response(200, [], '[]'),
            new Response(200, [], json_encode([['sessions' => $sessions]], JSON_THROW_ON_ERROR)),
        ]);

        $this->assertInvalidResponse(fn () => $client->tokens($this->token(['view-profile'])), 'devices.sessions');
    }

    public function testOnlineSessionIdentifiersMustAlsoBeStrings(): void
    {
        $client = $this->client([new Response(200, [], '[{"id":1}]')]);

        $this->assertInvalidResponse(fn () => $client->tokens($this->token(['view-profile'])), 'id');
    }

    public function testKeyedCollectionsKeepFilteringDefaultsAndNewestFirstOrdering(): void
    {
        $devices = ['device' => ['sessions' => [
            'online' => ['id' => 'online', 'clients' => [['clientId' => 'my-site']]],
            'no id' => ['clients' => [['clientId' => 'my-site']]],
            'null id' => ['id' => null],
            'other client' => ['id' => 'other', 'clients' => [['clientId' => 'another-site']]],
            'no clients' => ['id' => 'without-client'],
            'null clients' => ['id' => 'null-clients', 'clients' => null],
            'older' => ['id' => 'older', 'clients' => ['site' => ['clientId' => 'my-site']]],
            'newer' => [
                'id' => 'newer', 'started' => 100, 'lastAccess' => null, 'expires' => null,
                'ipAddress' => null, 'browser' => null, 'clients' => [['clientId' => 'my-site']],
            ],
        ]], 'empty' => ['sessions' => null], 'missing' => []];
        $client = $this->client([
            new Response(200, [], '{"current":{"id":"online"},"missing":{}}'),
            new Response(200, [], json_encode($devices, JSON_THROW_ON_ERROR)),
        ]);
        $tokens = $client->tokens($this->token(['view-profile']));

        $this->assertSame(['newer', 'older'], array_map(static fn ($token) => $token->id, $tokens));
        $this->assertSame(100, $tokens[0]->createdAt);
        foreach ($tokens as $token) {
            $this->assertSame(0, $token->lastUsedAt);
            $this->assertSame(0, $token->expiresAt);
            $this->assertNull($token->ip);
            $this->assertNull($token->browser);
        }
        $this->assertSame(0, $tokens[1]->createdAt);
    }

    public function testSessionLookupPreservesFieldsAndCredentialsStillDetectSecondFactors(): void
    {
        $record = ['id' => 'session', 'extra' => ['anything' => 1]];
        $client = $this->client([
            new Response(200, [], json_encode(['key' => $record], JSON_THROW_ON_ERROR)),
            new Response(200, [], '[]'),
            new Response(200, [], '[{"type":"password"},{"type":"otp","userCredentialMetadatas":[{}]}]'),
            new Response(200, [], '[{"type":"otp","userCredentialMetadatas":[]}]'),
        ]);
        $token = $this->token(['view-profile']);

        $this->assertSame($record, $client->session($token, 'session'));
        $this->assertNull($client->session($token, 'missing'));
        $this->assertTrue($client->hasSecondFactor($token));
        $this->assertFalse($client->hasSecondFactor($token));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function malformedPermissionClaims(): iterable
    {
        yield 'resource access as string' => [['resource_access' => 'invalid']];
        yield 'account as string' => [['resource_access' => ['account' => 'invalid']]];
        yield 'roles as string' => [['resource_access' => ['account' => ['roles' => 'view-profile']]]];
        yield 'roles as null' => [['resource_access' => ['account' => ['roles' => null]]]];
    }

    /** @param array<string, mixed> $claims */
    #[DataProvider('malformedPermissionClaims')]
    public function testMalformedPermissionClaimsKeepTheExistingForbiddenErrorWithoutHttp(array $claims): void
    {
        $payload = rtrim(strtr(base64_encode(json_encode($claims, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $token = 'eyJhbGciOiJSUzI1NiJ9.' . $payload . '.signature';
        $client = $this->client([]);
        foreach (['read', 'revoke'] as $action) {
            try {
                $action === 'read' ? $client->tokens($token) : $client->revoke($token, 'session');
                $this->fail('The required account permission must be checked.');
            } catch (AuthenticationException $e) {
                $this->assertSame(403, $e->getCode());
                $this->assertNull($e->getPrevious());
            }
        }
        $this->assertSame([], $this->requests);
    }

    /** @return iterable<string, array{int, int}> */
    public static function failedStatuses(): iterable
    {
        yield 'unauthorized' => [401, 403];
        yield 'forbidden' => [403, 403];
        yield 'not found' => [404, 400];
        yield 'server error' => [503, 400];
    }

    #[DataProvider('failedStatuses')]
    public function testHttpErrorsKeepTheirExistingAuthenticationStatus(int $status, int $expected): void
    {
        $client = $this->client([new Response($status)]);
        try {
            $client->session($this->token(['view-profile']), 'session');
            $this->fail('The failed HTTP response must be rejected.');
        } catch (AuthenticationException $e) {
            $this->assertSame($expected, $e->getCode());
            $this->assertStringContainsString('HTTP status ' . $status, $e->getMessage());
        }
    }

    public function testConnectionFailuresRemainProviderUnavailableErrors(): void
    {
        $previous = new ConnectException('Connection failed.', new Request('GET', 'https://keycloak.test'));
        $client = $this->client([$previous]);
        try {
            $client->session($this->token(['view-profile']), 'session');
            $this->fail('The unavailable provider must be reported.');
        } catch (ProviderUnavailableException $e) {
            $this->assertSame($previous, $e->getPrevious());
        }
    }

    public function testRevocationKeepsItsAcceptedAndRejectedStatuses(): void
    {
        $client = $this->client([new Response(200), new Response(404)]);
        $client->revoke($this->token(['manage-account']), 'session');
        try {
            $client->revoke($this->token(['manage-account']), 'session');
            $this->fail('The unsuccessful revocation must be reported.');
        } catch (AuthenticationException $e) {
            $this->assertSame(400, $e->getCode());
            $this->assertStringContainsString('HTTP status 404', $e->getMessage());
        }
    }
}
