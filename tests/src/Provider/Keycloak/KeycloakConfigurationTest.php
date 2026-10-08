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

use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The configuration of Keycloak: where the realm is, what the tokens must say,
 * how the HTTP client is made and where the user goes after the logout.
 */
#[CoversClass(KeycloakConfiguration::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(ConfigurationException::class)]
final class KeycloakConfigurationTest extends TestCase
{
    /**
     * @param array<string, mixed> $config
     */
    private function config(array $config = []): KeycloakConfiguration
    {
        return new KeycloakConfiguration($config + [
            'keycloak_url' => 'https://auth.example.com',
            'realm' => 'derafu',
            'client_id' => 'app',
            'client_secret' => 'secret',
            'redirect_uri' => 'https://app.example.com:8443/auth/callback',
        ]);
    }

    #[Test]
    public function theRealmUrlAndTheIssuerAreTheUrlOfTheRealm(): void
    {
        $config = $this->config(['keycloak_url' => 'https://auth.example.com/']);

        $this->assertSame('https://auth.example.com/realms/derafu', $config->getRealmUrl());
        $this->assertSame('https://auth.example.com/realms/derafu', $config->getIssuer());
    }

    #[Test]
    public function theIssuerCanBeConfigured(): void
    {
        $config = $this->config(['issuer' => 'https://public.example.com/realms/derafu']);

        $this->assertSame('https://public.example.com/realms/derafu', $config->getIssuer());
        $this->assertSame('https://auth.example.com/realms/derafu', $config->getRealmUrl());
    }

    #[Test]
    public function theLogoutOfKeycloakIsWantedByDefault(): void
    {
        $this->assertTrue($this->config()->isEndSession());
        $this->assertFalse($this->config(['end_session' => false])->isEndSession());
    }

    #[Test]
    public function theUserComesBackFromKeycloakToThePageThatFollowsTheLogout(): void
    {
        // In the site of the redirect URI (with its port).
        $this->assertSame(
            'https://app.example.com:8443/bye',
            $this->config(['logout_redirect_path' => '/bye'])->getPostLogoutRedirectUri()
        );
        $this->assertSame(
            'https://app.example.com:8443/',
            $this->config()->getPostLogoutRedirectUri()
        );
    }

    #[Test]
    public function thePostLogoutRedirectUriCanBeConfigured(): void
    {
        $this->assertSame(
            'https://other.example.com/goodbye',
            $this->config(['post_logout_redirect_uri' => 'https://other.example.com/goodbye'])->getPostLogoutRedirectUri()
        );
        $this->assertSame(
            'https://other.example.com/bye',
            $this->config(['logout_redirect_path' => 'https://other.example.com/bye'])->getPostLogoutRedirectUri()
        );
    }

    #[Test]
    public function theCertificateOfKeycloakIsVerifiedByDefault(): void
    {
        $this->assertTrue($this->config()->getHttpClientOptions()['verify']);
    }

    #[Test]
    public function theOptionsOfTheHttpClientThatAreNotSetKeepTheirDefaults(): void
    {
        // What an environment variable that is not set gives is null.
        $options = $this->config(['http_client_options' => ['timeout' => null, 'verify' => null, 'proxy' => 'http://p']])
            ->getHttpClientOptions();

        $this->assertTrue($options['verify']);
        $this->assertSame(30, $options['timeout']);
        $this->assertSame('http://p', $options['proxy']);
        $this->assertFalse($this->config(['http_client_options' => ['verify' => false]])->getHttpClientOptions()['verify']);
    }

    #[Test]
    public function theValuesAreReadByKeyAndAsAnArray(): void
    {
        $config = $this->config(['logout_redirect_path' => '/bye']);

        $this->assertSame('https://auth.example.com/realms/derafu', $config->get('issuer'));
        $this->assertTrue($config->get('end_session'));
        $this->assertSame('https://app.example.com:8443/bye', $config->get('post_logout_redirect_uri'));
        $this->assertSame('app', $config->toArray()['client_id']);
        $this->assertSame('https://auth.example.com/realms/derafu', $config->toArray()['issuer']);
        $this->assertTrue($config->toArray()['end_session']);
        $this->assertSame('https://app.example.com:8443/bye', $config->toArray()['post_logout_redirect_uri']);
    }

    #[Test]
    public function theCallbackIsTheLoginPath(): void
    {
        $this->assertSame('/auth/callback', $this->config()->getLoginPath());
        $this->assertSame('/in', $this->config(['callback_path' => '/in'])->getLoginPath());
    }

    #[Test]
    public function theClientAndTheRealmAreRequired(): void
    {
        foreach ([
            ['keycloak_url' => '', 'message' => 'Keycloak URL is required.'],
            ['client_id' => '', 'message' => 'Client ID is required.'],
            ['client_secret' => '', 'message' => 'Client secret is required.'],
            ['redirect_uri' => '', 'message' => 'Redirect URI is required.'],
        ] as $case) {
            $message = $case['message'];
            unset($case['message']);

            try {
                $this->config($case)->validate();
                $this->fail('It should have failed: ' . $message);
            } catch (ConfigurationException $e) {
                $this->assertSame($message, $e->getMessage());
            }
        }

        $this->config()->validate();
    }

    #[Test]
    public function theRefreshIntervalIsAutomaticByDefaultWhichIsTheExpirationOfTheToken(): void
    {
        $config = $this->config();

        $this->assertNull($config->getRefreshInterval());
        $this->assertNull($config->get('refresh_interval'));
        $this->assertArrayHasKey('refresh_interval', $config->toArray());
        $this->assertNull($config->toArray()['refresh_interval']);
    }

    #[Test]
    public function theRefreshIntervalCanBeConfiguredAndZeroIsAutomatic(): void
    {
        $this->assertSame(120, $this->config(['refresh_interval' => 120])->getRefreshInterval());
        $this->assertSame(120, $this->config(['refresh_interval' => 120])->toArray()['refresh_interval']);
        $this->assertNull($this->config(['refresh_interval' => 0])->getRefreshInterval());
    }

    #[Test]
    public function aNegativeRefreshIntervalIsAConfigurationError(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The refresh interval must be a number of seconds, 0 or more.');

        $this->config(['refresh_interval' => -5]);
    }

    #[Test]
    public function theClientOfTheApiIsTheClientOfTheApplicationUnlessItHasItsOwn(): void
    {
        $config = $this->config();

        $this->assertSame('app', $config->getApiClientId());
        $this->assertSame('secret', $config->getApiClientSecret());
        $this->assertSame('app', $config->getApiAudience());

        $config = $this->config(['api_client_id' => 'billing-api', 'api_client_secret' => 'api-secret']);

        $this->assertSame('billing-api', $config->getApiClientId());
        $this->assertSame('api-secret', $config->getApiClientSecret());
        $this->assertSame('billing-api', $config->getApiAudience(), 'The audience is the client that asks.');
        $this->assertSame('app', $config->getClientId(), 'The login keeps its client.');
        $this->assertSame('billing-api', $config->get('api_client_id'));
        $this->assertSame('api-secret', $config->get('api_client_secret'));
        $this->assertSame('billing-api', $config->toArray()['api_client_id']);
        $this->assertSame('api-secret', $config->toArray()['api_client_secret']);
    }

    #[Test]
    public function theClientOfTheApiNeedsItsIdAndItsSecret(): void
    {
        foreach ([['api_client_id' => 'billing-api'], ['api_client_secret' => 'api-secret']] as $half) {
            try {
                $this->config($half);
                $this->fail('A half of the client of the API was accepted.');
            } catch (ConfigurationException $e) {
                $this->assertStringContainsString('both', $e->getMessage());
            }
        }
    }

    #[Test]
    public function theAudienceMustBeTheClientOfTheApiWhenKeycloakIsAsked(): void
    {
        $api = ['api_client_id' => 'billing-api', 'api_client_secret' => 'api-secret'];

        // The client of the application is not the one that asks any more.
        $this->expectException(ConfigurationException::class);
        $this->config($api + ['api_audience' => 'app']);
    }

    #[Test]
    public function theAudienceIsTheClientOfTheApiWhenItIsTheSame(): void
    {
        $config = $this->config([
            'api_client_id' => 'billing-api',
            'api_client_secret' => 'api-secret',
            'api_audience' => 'billing-api',
        ]);

        $this->assertSame('billing-api', $config->getApiAudience());
    }
}
