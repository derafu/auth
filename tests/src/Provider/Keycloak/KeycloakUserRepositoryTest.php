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
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use League\OAuth2\Client\Provider\GenericProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Tests for KeycloakUserRepository.
 */
#[CoversClass(KeycloakUserRepository::class)]
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
        $this->assertIsString($state1);
        $this->assertIsString($state2);
    }
}
