<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Integration;

use Derafu\Auth\Adapter\KeycloakAuthenticationAdapter;
use Derafu\Auth\Configuration\AuthConfiguration;
use Derafu\Auth\User\KeycloakUser;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use Mezzio\Authentication\UserInterface;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeycloakAuthenticationAdapter::class)]
#[CoversClass(AuthConfiguration::class)]
#[CoversClass(KeycloakUser::class)]
class KeycloakAuthenticationFlowTest extends TestCase
{
    private AuthConfiguration $config;

    private MockHandler $mockHandler;

    protected function setUp(): void
    {
        $this->mockHandler = new MockHandler();
        $handlerStack = HandlerStack::create($this->mockHandler);

        $this->config = new AuthConfiguration([
            'keycloak_url' => 'http://localhost:8080',
            'realm' => 'test-realm',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'http://localhost/auth/callback',
            'protected_routes' => ['/dashboard', '/admin'],
            'callback_route' => '/auth/callback',
            'logout_route' => '/auth/logout',
            'http_client_options' => [
                'handler' => $handlerStack,
            ],
        ]);
    }

    #[Test]
    public function testUnauthorizedResponseRedirectsToKeycloak(): void
    {
        $adapter = new KeycloakAuthenticationAdapter($this->config);
        $session = new Session(['id' => 'test-session']);

        // Create request to protected route.
        $request = new ServerRequest();
        $request = $request->withUri(new Uri('http://localhost/dashboard'));
        $request = $request->withAttribute('session', $session);

        $response = $adapter->unauthorizedResponse($request);

        // Should redirect to Keycloak authorization URL.
        $this->assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        $this->assertStringContainsString('http://localhost:8080/realms/test-realm/protocol/openid-connect/auth', $location);
        $this->assertStringContainsString('client_id=test-client', $location);
        $this->assertStringContainsString('redirect_uri=http%3A%2F%2Flocalhost%2Fauth%2Fcallback', $location);
    }

    #[Test]
    public function testLogoutFlow(): void
    {
        $adapter = new KeycloakAuthenticationAdapter($this->config);
        $session = new Session(['id' => 'test-session']);

        // Store some auth data.
        $session->set('oauth2_token', 'some-token');
        $session->set('user', ['sub' => 'user-123']);

        // Request logout route.
        $request = new ServerRequest();
        $request = $request->withUri(new Uri('http://localhost/auth/logout'));
        $request = $request->withAttribute('session', $session);

        $user = $adapter->authenticate($request);

        // Should return null and clear session.
        $this->assertNull($user);
        $this->assertNull($session->get('oauth2_token'));
        $this->assertNull($session->get('user'));
    }

    #[Test]
    public function testAlreadyAuthenticatedUser(): void
    {
        $adapter = new KeycloakAuthenticationAdapter($this->config);
        $session = new Session(['id' => 'test-session']);

        // Store valid auth data.
        $session->set('oauth2_token', 'valid-token');
        $session->set('oauth2_expiry', time() + 3600);
        $session->set('user', [
            'sub' => 'user-123',
            'email' => 'test@example.com',
            'name' => 'Test User',
        ]);

        $request = new ServerRequest();
        $request = $request->withUri(new Uri('http://localhost/dashboard'));
        $request = $request->withAttribute('session', $session);

        $user = $adapter->authenticate($request);

        // Should return existing user without making HTTP requests.
        $this->assertInstanceOf(UserInterface::class, $user);
        $this->assertSame('user-123', $user->getIdentity());
    }

    #[Test]
    public function testCallbackWithInvalidStateParameter(): void
    {
        $adapter = new KeycloakAuthenticationAdapter($this->config);
        $session = new Session(['id' => 'test-session']);

        // Store a state parameter.
        $session->set('oauth2_state', 'valid-state');

        // Simulate callback with invalid state.
        $callbackRequest = new ServerRequest();
        $callbackRequest = $callbackRequest->withUri(new Uri('http://localhost/auth/callback?code=auth-code&state=invalid-state'));
        $callbackRequest = $callbackRequest->withAttribute('session', $session);

        $user = $adapter->authenticate($callbackRequest);

        // Should return null due to CSRF protection.
        $this->assertNull($user);
        $this->assertNull($session->get('oauth2_state')); // State should be cleared.
    }

    #[Test]
    public function testConfigurationValidation(): void
    {
        // Test that configuration is properly validated.
        $this->assertSame('http://localhost:8080', $this->config->getKeycloakUrl());
        $this->assertSame('test-realm', $this->config->getRealm());
        $this->assertSame('test-client', $this->config->getClientId());
        $this->assertSame('test-secret', $this->config->getClientSecret());
        $this->assertSame('http://localhost/auth/callback', $this->config->getRedirectUri());
        $this->assertSame('/auth/callback', $this->config->getCallbackRoute());
        $this->assertSame('/auth/logout', $this->config->getLogoutRoute());
    }

    #[Test]
    public function testUserCreationWithValidData(): void
    {
        $userInfo = [
            'sub' => 'user-123',
            'email' => 'test@example.com',
            'name' => 'Test User',
            'preferred_username' => 'testuser',
            'realm_access' => [
                'roles' => ['user', 'admin'],
            ],
            'resource_access' => [
                'test-client' => [
                    'roles' => ['read', 'write'],
                ],
            ],
        ];

        $user = new KeycloakUser($userInfo);

        $this->assertSame('user-123', $user->getIdentity());
        $this->assertSame('test@example.com', $user->getDetail('email'));
        $this->assertSame('Test User', $user->getDetail('name'));

        // Check roles.
        $roles = iterator_to_array($user->getRoles());
        $this->assertContains('user', $roles);
        $this->assertContains('admin', $roles);
        $this->assertContains('read', $roles);
        $this->assertContains('write', $roles);
    }
}
