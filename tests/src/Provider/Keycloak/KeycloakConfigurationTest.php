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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The configuration of Keycloak: where the realm is, what the tokens must say,
 * how the HTTP client is made and where the user goes after the logout.
 */
#[CoversClass(KeycloakConfiguration::class)]
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
            $this->config()->getPostLogoutRedirectUri('/bye')
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
            $this->config()->getPostLogoutRedirectUri('https://other.example.com/bye')
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
    public function theRequestsToKeycloakSayWhoMakesThem(): void
    {
        $this->assertSame('Derafu Auth (app)', $this->config()->getHttpClientOptions()['headers']['User-Agent']);
        $this->assertSame('Derafu Auth (app)', $this->config()->getUserAgent());
    }

    #[Test]
    public function theUserAgentOfTheApplicationIsKept(): void
    {
        $options = $this->config(['http_client_options' => ['headers' => ['user-agent' => 'My site', 'X-Other' => '1']]])
            ->getHttpClientOptions();

        $this->assertSame(['user-agent' => 'My site', 'X-Other' => '1'], $options['headers']);
    }

    #[Test]
    public function theUserAgentHasNothingThatAHeaderCanNotHave(): void
    {
        $config = $this->config(['client_id' => "my site\r\nX-Evil: 1\u{00f1}"]);

        $this->assertSame('Derafu Auth (mysiteX-Evil:1)', $config->getUserAgent());
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

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function provideWhatTheWebNeeds(): array
    {
        return [
            'no URL' => [['keycloak_url' => ''], 'The URL of Keycloak is not configured: set AUTH_KEYCLOAK_URL.'],
            'a URL without scheme' => [['keycloak_url' => 'auth.example.com'], 'The value of AUTH_KEYCLOAK_URL "auth.example.com" is not valid: it must be an address that starts with http:// or https://.'],
            'no realm' => [['realm' => ''], 'The realm of Keycloak is not configured: set AUTH_KEYCLOAK_REALM.'],
            'no client' => [['client_id' => ''], 'The client of Keycloak is not configured: set AUTH_KEYCLOAK_CLIENT_ID.'],
            'no secret' => [['client_secret' => ''], 'The secret of the client of Keycloak is not configured: set AUTH_KEYCLOAK_CLIENT_SECRET.'],
            'no redirect URI' => [['redirect_uri' => ''], 'The redirect URI of Keycloak is not configured: set AUTH_KEYCLOAK_WEB_REDIRECT_URI.'],
            'a redirect URI that is a path' => [['redirect_uri' => '/auth/callback'], 'The value of AUTH_KEYCLOAK_WEB_REDIRECT_URI "/auth/callback" is not valid: it must be an address that starts with http:// or https://.'],
        ];
    }

    /**
     * @param array<string, mixed> $case
     */
    #[Test]
    #[DataProvider('provideWhatTheWebNeeds')]
    public function theLoginNeedsTheUrlTheRealmAndTheClientAndSaysWhichVariable(array $case, string $message): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($message);

        $this->config($case)->validateWeb();
    }

    #[Test]
    public function aConfigurationThatHasWhatTheLoginNeedsIsValid(): void
    {
        $this->config()->validateWeb();

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function theApiDoesNotNeedWhatOnlyTheLoginNeeds(): void
    {
        // No redirect URI: a service that only verifies tokens does not log anybody in.
        $this->config(['redirect_uri' => ''])->validateApi();

        $this->addToAssertionCount(1);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function provideWhatTheApiNeeds(): array
    {
        return [
            'no URL' => [['keycloak_url' => ''], 'The URL of Keycloak is not configured: set AUTH_KEYCLOAK_URL.'],
            'no realm' => [['realm' => ''], 'The realm of Keycloak is not configured: set AUTH_KEYCLOAK_REALM.'],
            'a half of the client of the API' => [['api_client_id' => 'billing-api'], 'The client of the API needs its ID and its secret, both: set AUTH_KEYCLOAK_API_CLIENT_ID and AUTH_KEYCLOAK_API_CLIENT_SECRET.'],
            'the other half' => [['api_client_secret' => 'api-secret'], 'The client of the API needs its ID and its secret, both: set AUTH_KEYCLOAK_API_CLIENT_ID and AUTH_KEYCLOAK_API_CLIENT_SECRET.'],
            'no audience' => [['client_id' => ''], 'The audience of the API is not configured: set AUTH_KEYCLOAK_API_AUDIENCE, or the client with AUTH_KEYCLOAK_CLIENT_ID.'],
            'no client to ask with' => [['client_secret' => ''], 'Keycloak is asked about the tokens with a client, and it is not configured: set AUTH_KEYCLOAK_CLIENT_ID and AUTH_KEYCLOAK_CLIENT_SECRET (or the ones of the API, AUTH_KEYCLOAK_API_CLIENT_ID and AUTH_KEYCLOAK_API_CLIENT_SECRET), or turn the introspection off with AUTH_KEYCLOAK_API_INTROSPECTION=false.'],
        ];
    }

    /**
     * @param array<string, mixed> $case
     */
    #[Test]
    #[DataProvider('provideWhatTheApiNeeds')]
    public function theApiNeedsTheRealmTheAudienceAndAClientAndSaysWhichVariable(array $case, string $message): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($message);

        $this->config($case)->validateApi();
    }

    #[Test]
    public function withoutIntrospectionTheApiDoesNotNeedASecret(): void
    {
        $this->config(['client_secret' => '', 'api_introspection' => false])->validateApi();

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function theAudienceMustBeTheClientOfTheApiWhenKeycloakIsAsked(): void
    {
        $api = ['api_client_id' => 'billing-api', 'api_client_secret' => 'api-secret'];

        // The client of the application is not the one that asks any more.
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The audience of the API "app" is not the client "billing-api"');

        $this->config($api + ['api_audience' => 'app'])->validateApi();
    }

    #[Test]
    public function anotherAudienceIsFineWhenKeycloakIsNotAsked(): void
    {
        $this->config(['api_audience' => 'billing', 'api_introspection' => false])->validateApi();

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function aConfigurationThatIsNotValidDoesNotFailUntilItIsChecked(): void
    {
        // It is made in every request that uses the provider: it must not fail
        // there, but where Keycloak is needed.
        $config = $this->config(['api_client_id' => 'billing-api', 'api_audience' => 'app']);

        $this->assertSame('app', $config->getApiAudience());
    }
}
