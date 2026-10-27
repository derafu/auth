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

use Derafu\Auth\Authentication\Channel\Web\FormManager;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakAccount;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakAccountClient;
use Derafu\Auth\Provider\Keycloak\Account\KeycloakApiTokenManager;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\SessionApp;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\Attributes\UsesNamespace;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * The session details remain available when the account API cannot be read.
 */
#[CoversClass(KeycloakAccount::class)]
#[UsesClass(KeycloakAccountClient::class)]
#[UsesClass(KeycloakApiTokenManager::class)]
#[UsesClass(KeycloakConfiguration::class)]
#[UsesClass(KeycloakTokenVerifier::class)]
#[UsesClass(KeycloakUserRepository::class)]
#[UsesClass(TokenClaims::class)]
#[UsesClass(KeycloakSessionManager::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(ProviderUnavailableException::class)]
#[UsesClass(FormManager::class)]
#[UsesNamespace('Derafu\\Auth')]
final class KeycloakAccountTest extends TestCase
{
    private function account(Response|Throwable $answer, string $redirect = 'https://app.test/auth/callback'): KeycloakAccount
    {
        $config = new KeycloakConfiguration([
            'keycloak_url' => 'https://keycloak.test', 'realm' => 'test', 'client_id' => 'app',
            'client_secret' => 'secret', 'redirect_uri' => $redirect,
        ]);
        $http = new Client(['handler' => HandlerStack::create(new MockHandler([$answer]))]);
        $client = new KeycloakAccountClient($config, $http);
        $sessions = new KeycloakSessionManager();
        $forms = new FormManager(
            new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
            (new SessionApp())->processor(),
            $config
        );

        return new KeycloakAccount(
            $config,
            $sessions,
            $client,
            new KeycloakApiTokenManager(new KeycloakUserRepository($config, httpClient: $http), $client, $sessions, $forms)
        );
    }

    private function session(): Session
    {
        $claims = [
            'sid' => 'session-1', 'iat' => 1700000000, 'exp' => 1800000000,
            'resource_access' => ['account' => ['roles' => ['view-profile']]],
        ];
        $payload = rtrim(strtr(base64_encode(json_encode($claims, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        return new Session(['oauth2_token' => 'eyJhbGciOiJSUzI1NiJ9.' . $payload . '.signature']);
    }

    #[Test]
    #[DataProvider('accountFailures')]
    public function tokenDetailsRemainAvailableWhenTheAccountApiFails(Response|Throwable $answer): void
    {
        $sections = $this->account($answer)->sessionDetails($this->session());

        $this->assertCount(1, $sections);
        $this->assertSame('Keycloak token', (string) $sections[0]['title']);
        $values = array_column($sections[0]['fields'], 'value');
        $this->assertContains('session-1', $values);
        $this->assertContains(date('Y-m-d H:i:s', 1800000000), $values);
    }

    /** @return iterable<string, array{Response|Throwable}> */
    public static function accountFailures(): iterable
    {
        yield 'permission denied' => [new Response(403)];
        yield 'provider unavailable' => [new ConnectException('Connection failed', new Request('GET', 'https://keycloak.test/realms/test/account/sessions'))];
    }

    #[Test]
    public function knownSessionDetailsAreAddedWhenTheAccountApiIsAvailable(): void
    {
        $answer = new Response(200, [], json_encode([[
            'id' => 'session-1', 'started' => 1700000000, 'lastAccess' => 1700000100,
            'expires' => 1800000000, 'ipAddress' => '203.0.113.7', 'browser' => 'Firefox',
        ]], JSON_THROW_ON_ERROR));
        $sections = $this->account($answer)->sessionDetails($this->session());

        $this->assertCount(2, $sections);
        $this->assertSame('Session in Keycloak', (string) $sections[1]['title']);
        $values = array_column($sections[1]['fields'], 'value');
        $this->assertContains('203.0.113.7', $values);
        $this->assertContains('Firefox', $values);
    }

    #[Test]
    public function thePublicUrlUsesOnlyTheConfiguredOriginAndKeepsItsPort(): void
    {
        $account = $this->account(new Response(200), 'https://app.test:8443/auth/callback?state=secret');

        $this->assertSame('https://app.test:8443', $account->publicUrl());
    }

    #[Test]
    public function aRelativeRedirectUriDoesNotInventAPublicOrigin(): void
    {
        $this->assertNull($this->account(new Response(200), '/auth/callback')->publicUrl());
    }
}
