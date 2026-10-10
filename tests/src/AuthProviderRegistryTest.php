<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth;

use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\AuthProviderRegistry;
use Derafu\Auth\Contract\AccountInterface;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\AuthProviderInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Exception\ConfigurationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ServiceLocator;

/**
 * The provider of the application is the one that `AUTH_PROVIDER` names: the
 * registry gives what it gives, and says what to set when there is none.
 */
#[CoversClass(AuthProviderRegistry::class)]
#[UsesClass(WebConfiguration::class)]
#[UsesClass(ConfigurationException::class)]
final class AuthProviderRegistryTest extends TestCase
{
    private AuthProviderInterface $database;

    private AuthProviderInterface $keycloak;

    protected function setUp(): void
    {
        $this->database = $this->providerOf(['logout_redirect_path' => '/auth/login']);
        $this->keycloak = $this->providerOf([]);
    }

    /**
     * @param array<string, string> $defaults
     */
    private function providerOf(array $defaults): AuthProviderInterface
    {
        $provider = $this->createStub(AuthProviderInterface::class);
        $provider->method('webDefaults')->willReturn($defaults);
        $provider->method('webFlow')->willReturn($this->createStub(WebFlowInterface::class));
        $provider->method('sessionManager')->willReturn($this->createStub(SessionManagerInterface::class));
        $provider->method('forms')->willReturn($this->createStub(FormManagerInterface::class));
        $provider->method('apiScheme')->willReturn($this->createStub(ApiSchemeInterface::class));
        $provider->method('account')->willReturn($this->createStub(AccountInterface::class));

        return $provider;
    }

    private function registry(string $name): AuthProviderRegistry
    {
        return new AuthProviderRegistry(new ServiceLocator([
            'database' => fn () => $this->database,
            'keycloak' => fn () => $this->keycloak,
        ]), $name);
    }

    #[Test]
    public function itGivesTheProviderThatTheNameSays(): void
    {
        $this->assertSame($this->database, $this->registry('database')->provider());
        $this->assertSame($this->keycloak, $this->registry('keycloak')->provider());
    }

    #[Test]
    public function itGivesWhatTheChosenProviderGives(): void
    {
        $registry = $this->registry('database');

        $this->assertSame($this->database->webFlow(), $registry->webFlow());
        $this->assertSame($this->database->sessionManager(), $registry->sessionManager());
        $this->assertSame($this->database->forms(), $registry->forms());
        $this->assertSame($this->database->apiScheme(), $registry->apiScheme());
        $this->assertSame($this->database->account(), $registry->account());
        // And not what the other gives.
        $this->assertNotSame($this->keycloak->webFlow(), $registry->webFlow());
    }

    #[Test]
    public function withoutAProviderTheErrorSaysWhichOnesThereAre(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('AUTH_PROVIDER is not set. Choose one of: database, keycloak.');

        $this->registry('')->webFlow();
    }

    #[Test]
    public function aVariableThatIsNotSetIsTheSameAsOneThatIsEmpty(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('AUTH_PROVIDER is not set. Choose one of: database, keycloak.');

        (new AuthProviderRegistry(new ServiceLocator(['database' => fn () => $this->database, 'keycloak' => fn () => $this->keycloak]), null))->provider();
    }

    #[Test]
    public function aProviderThatIsNotKnownIsAnErrorThatSaysTheNameAndWhichOnesThereAre(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('AUTH_PROVIDER "ldap" is not a provider. Choose one of: database, keycloak.');

        $this->registry('ldap')->provider();
    }

    #[Test]
    public function aRegistryWithoutProvidersSaysSo(): void
    {
        $registry = new AuthProviderRegistry(new ServiceLocator([]), 'database');

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('There are no providers: tag the service of each one with derafu_auth.provider.');

        $registry->provider();
    }

    #[Test]
    public function theWebConfigurationHasThePathsThatTheProviderAsksFor(): void
    {
        $config = $this->registry('database')->webConfiguration([]);

        $this->assertSame('/auth/login', $config->getLogoutRedirectPath());
        // What the provider does not say is the default of the package.
        $this->assertSame('/', $config->getLoginRedirectPath());
    }

    #[Test]
    public function whatTheApplicationSaysWinsOverWhatTheProviderAsksFor(): void
    {
        $config = $this->registry('database')->webConfiguration([
            'logout_redirect_path' => '/bye',
            'login_redirect_path' => null,
        ]);

        $this->assertSame('/bye', $config->getLogoutRedirectPath());
        // A variable that is not set (null) does not win.
        $this->assertSame('/', $config->getLoginRedirectPath());
    }

    #[Test]
    public function aProviderThatAsksForNothingLeavesThePathsOfThePackage(): void
    {
        $config = $this->registry('keycloak')->webConfiguration([]);

        $this->assertSame('/', $config->getLogoutRedirectPath());
        $this->assertSame('/auth/logout', $config->getLogoutPath());
    }

    #[Test]
    public function theWebConfigurationDoesNotFailWithoutAProvider(): void
    {
        // The pages that do not use the provider (the paths are in the menu) keep
        // working: the error is told where the provider is needed.
        $config = $this->registry('')->webConfiguration(['logout_redirect_path' => '/bye']);

        $this->assertSame('/bye', $config->getLogoutRedirectPath());
        $this->assertSame('/', $config->getLoginRedirectPath());
    }
}
