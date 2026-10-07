<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Tests\Provider\Keycloak;

use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\GenericProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Throwable;

/**
 * Tests for KeycloakUserRepository.
 */
#[CoversClass(KeycloakUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier::class)]
#[CoversClass(KeycloakConfiguration::class)]
#[CoversClass(AuthenticationException::class)]
class KeycloakUserRepositoryTest extends TestCase
{
    private KeycloakConfiguration $config;

    private KeycloakUserRepository $repository;

    protected function setUp(): void
    {
        $this->config = new KeycloakConfiguration([
            'keycloak_url' => 'https://auth.example.com',
            'realm' => 'test-realm',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.example.com/auth/callback',
            'scopes' => ['openid', 'profile', 'email'],
        ]);

        $this->repository = new KeycloakUserRepository($this->config);
    }

    #[Test]
    public function testCreateAuthorizationUrlContainsCorrectScopes(): void
    {
        // Test that scopes are formatted correctly as space-separated string
        $authUrl = $this->repository->createAuthorizationUrl();

        // Parse the URL to check the scope parameter
        $urlParts = parse_url($authUrl);
        parse_str($urlParts['query'] ?? '', $queryParams);

        $this->assertArrayHasKey('scope', $queryParams);
        $this->assertSame('openid profile email', $queryParams['scope']);
        $this->assertStringContainsString('response_type=code', $authUrl);
        $this->assertStringContainsString('client_id=test-client', $authUrl);
    }

    #[Test]
    public function testCreateAuthorizationUrlWithCustomScopes(): void
    {
        // Test with custom scopes in configuration
        $customConfig = new KeycloakConfiguration([
            'keycloak_url' => 'https://auth.example.com',
            'realm' => 'test-realm',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.example.com/auth/callback',
            'scopes' => ['openid', 'custom-scope'],
        ]);

        $repository = new KeycloakUserRepository($customConfig);
        $authUrl = $repository->createAuthorizationUrl();

        $urlParts = parse_url($authUrl);
        parse_str($urlParts['query'] ?? '', $queryParams);

        $this->assertSame('openid custom-scope', $queryParams['scope']);
    }

    #[Test]
    public function testCreateAuthorizationUrlWithAdditionalOptions(): void
    {
        // Test that additional options are merged correctly
        $authUrl = $this->repository->createAuthorizationUrl([
            'custom_param' => 'custom_value',
            'prompt' => 'consent',
        ]);

        $urlParts = parse_url($authUrl);
        parse_str($urlParts['query'] ?? '', $queryParams);

        // Our configured scopes should be present
        $this->assertSame('openid profile email', $queryParams['scope']);
        $this->assertSame('custom_value', $queryParams['custom_param']);
        $this->assertSame('consent', $queryParams['prompt']);
    }

    #[Test]
    public function testProviderIsConfiguredCorrectly(): void
    {
        // Use reflection to access the private provider property
        $reflection = new ReflectionClass($this->repository);
        $providerProperty = $reflection->getProperty('provider');

        /** @var GenericProvider $provider */
        $provider = $providerProperty->getValue($this->repository);

        // Test that URLs are constructed correctly
        $this->assertInstanceOf(GenericProvider::class, $provider);

        // Use reflection to check provider configuration
        $providerReflection = new ReflectionClass($provider);
        $urlAuthorizeProperty = $providerReflection->getProperty('urlAuthorize');
        $urlAccessTokenProperty = $providerReflection->getProperty('urlAccessToken');
        $urlResourceOwnerDetailsProperty = $providerReflection->getProperty('urlResourceOwnerDetails');

        $this->assertSame(
            'https://auth.example.com/realms/test-realm/protocol/openid-connect/auth',
            $urlAuthorizeProperty->getValue($provider)
        );
        $this->assertSame(
            'https://auth.example.com/realms/test-realm/protocol/openid-connect/token',
            $urlAccessTokenProperty->getValue($provider)
        );
        $this->assertSame(
            'https://auth.example.com/realms/test-realm/protocol/openid-connect/userinfo',
            $urlResourceOwnerDetailsProperty->getValue($provider)
        );
    }

    #[Test]
    public function testIsTokenValidWithInvalidToken(): void
    {
        // Test that isTokenValid returns false for obviously invalid tokens
        $result = $this->repository->isTokenValid('clearly-invalid-token');

        // Should return false since it can't validate against real Keycloak
        $this->assertFalse($result);
    }

    #[Test]
    public function testStateParameterGeneration(): void
    {
        // Test that state parameter is generated after creating auth URL
        $this->repository->createAuthorizationUrl();
        $state1 = $this->repository->getState();

        $this->repository->createAuthorizationUrl();
        $state2 = $this->repository->getState();

        // States should be different (random)
        $this->assertNotEmpty($state1);
        $this->assertNotEmpty($state2);
        $this->assertNotSame($state1, $state2);
    }

    #[Test]
    public function theHttpOptionsOfTheConfigurationAreTheOnesOfTheClientThatAsksTheTokens(): void
    {
        // They were given to a client that the provider threw away for one of its
        // own, so a server that did not answer was waited for with no end, and a
        // certificate that was not to be verified was verified.
        $repository = new KeycloakUserRepository(new KeycloakConfiguration([
            'keycloak_url' => 'https://auth.example.com',
            'realm' => 'test-realm',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.example.com/auth/callback',
            'http_client_options' => ['timeout' => 7, 'connect_timeout' => 3, 'verify' => false],
        ]));

        $client = $repository->getProvider()->getHttpClient();

        $this->assertSame(7, $client->getConfig('timeout'));
        $this->assertSame(3, $client->getConfig('connect_timeout'));
        $this->assertFalse($client->getConfig('verify'));
    }

    /**
     * A repository whose provider gets these answers, one for each request.
     */
    private function repositoryAnswering(Response|Throwable ...$answers): KeycloakUserRepository
    {
        return new KeycloakUserRepository(new KeycloakConfiguration([
            'keycloak_url' => 'https://auth.example.com',
            'realm' => 'test-realm',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.example.com/auth/callback',
            'http_client_options' => ['handler' => HandlerStack::create(new MockHandler($answers))],
        ]));
    }

    #[Test]
    public function aRefreshTokenThatKeycloakRejectsIsARejectionOfTheSession(): void
    {
        $repository = $this->repositoryAnswering(new Response(400, [], json_encode([
            'error' => 'invalid_grant',
            'error_description' => 'Token is not active',
        ])));

        try {
            $repository->refreshToken('a-refresh-token');
            $this->fail('It should have failed.');
        } catch (AuthenticationException $e) {
            $this->assertNotInstanceOf(ProviderUnavailableException::class, $e);
            $this->assertStringStartsWith('Failed to refresh token: ', $e->getMessage());
        }
    }

    /**
     * @return array<string, array{Response|Throwable}>
     */
    public static function failuresThatSayNothingOfTheSessionProvider(): array
    {
        return [
            'the server does not answer' => [new ConnectException('Operation timed out', new Request('POST', '/'))],
            'the server is down' => [new Response(503, ['Content-Type' => 'text/html'], '<html>Service Unavailable</html>')],
            'the server fails' => [new Response(500, [], json_encode(['error' => 'unknown_error']))],
            'the client is not known' => [new Response(401, [], json_encode([
                'error' => 'unauthorized_client',
                'error_description' => 'Invalid client or Invalid client credentials',
            ]))],
            'the answer is not a token' => [new Response(200, [], json_encode(['hello' => 'world']))],
        ];
    }

    #[Test]
    #[DataProvider('failuresThatSayNothingOfTheSessionProvider')]
    public function whatIsNotAboutTheRefreshTokenIsNotARejectionOfTheSession(Response|Throwable $answer): void
    {
        $repository = $this->repositoryAnswering($answer);

        try {
            $repository->refreshToken('a-refresh-token');
            $this->fail('It should have failed.');
        } catch (ProviderUnavailableException $e) {
            // The session may be as good as it was: it can not be known now.
            $this->assertStringStartsWith('Failed to refresh token: ', $e->getMessage());
        }
    }
}
