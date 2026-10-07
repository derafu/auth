<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth;

use Derafu\Auth\Provider\Database\DatabaseAuthentication;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\LoginThrottle;
use Derafu\Auth\Provider\Keycloak\KeycloakAuthentication;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\DataProcessor\ProcessorFactory;
use Derafu\Form\Contract\Factory\FormFactoryInterface;
use Derafu\Form\Contract\Processor\FormDataProcessorInterface;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Processor\FormDataProcessor;
use Derafu\Form\Processor\FormRulesResolver;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Mezzio\Authentication\AuthenticationInterface;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;
use ReflectionProperty;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * The services of the package, as an application imports them: what the
 * container gives with the configuration of the environment, and with the cache
 * pool that the application has (or does not have).
 */
#[CoversNothing]
final class ServicesTest extends TestCase
{
    /**
     * @var list<string>
     */
    private array $environment = [];

    protected function tearDown(): void
    {
        foreach ($this->environment as $name) {
            putenv($name);
        }
        $this->environment = [];
    }

    private function environment(string $name, string $value): void
    {
        putenv($name . '=' . $value);
        $this->environment[] = $name;
    }

    /**
     * The container of an application that imports the services of a provider.
     */
    private function container(string $services, bool $withPool): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.project_dir', dirname(__DIR__, 2));

        if ($withPool) {
            $container->register(CacheItemPoolInterface::class, ArrayAdapter::class)->setPublic(true);
        }

        // What the forms need (the database provider uses them).
        $container->register(FormFactoryInterface::class, FormFactory::class)->setArguments([
            new Definition(TypeResolver::class, [new Definition(TypeRegistry::class, [new Definition(TypeProvider::class)])]),
        ]);
        $container->register(FormDataProcessorInterface::class, FormDataProcessor::class)->setArguments([
            new Definition(FormRulesResolver::class),
            (new Definition(\Derafu\DataProcessor\Contract\ProcessorInterface::class))
                ->setFactory([ProcessorFactory::class, 'create']),
        ]);

        // The renderer that the login page of the database provider needs.
        $container->register(\Derafu\Renderer\Contract\RendererInterface::class)
            ->setFactory([\Derafu\Renderer\Factory\RendererFactory::class, 'create'])
            ->setArguments([['engines' => ['twig'], 'extra' => false]]);

        (new YamlFileLoader($container, new FileLocator(dirname(__DIR__, 2) . '/resources/config')))->load($services);

        return $container;
    }

    private function property(object $object, string $name): mixed
    {
        return (new ReflectionProperty($object::class, $name))->getValue($object);
    }

    #[Test]
    public function theVerifierOfKeycloakCachesTheKeysInThePoolOfTheApplication(): void
    {
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakTokenVerifier::class)->setPublic(true);
        $container->getDefinition(KeycloakUserRepository::class)->setPublic(true);
        $container->compile(true);

        $verifier = $container->get(KeycloakTokenVerifier::class);

        $this->assertSame($container->get(CacheItemPoolInterface::class), $this->property($verifier, 'cache'));
        // The repository verifies with that verifier.
        $this->assertSame($verifier, $this->property($container->get(KeycloakUserRepository::class), 'verifier'));
    }

    #[Test]
    public function theVerifierOfKeycloakWorksWithoutAPoolButDoesNotCache(): void
    {
        $container = $this->container('auth-keycloak-services.yaml', false);
        $container->getDefinition(KeycloakTokenVerifier::class)->setPublic(true);
        $container->compile(true);

        $this->assertNull($this->property($container->get(KeycloakTokenVerifier::class), 'cache'));
    }

    #[Test]
    public function theConfigurationOfKeycloakIsTheOneOfTheEnvironmentWithSafeDefaults(): void
    {
        $this->environment('KEYCLOAK_URL', 'https://auth.example.com');
        $this->environment('KEYCLOAK_REALM', 'derafu');
        $this->environment('KEYCLOAK_CLIENT_ID', 'app');
        $this->environment('KEYCLOAK_CLIENT_SECRET', 'secret');
        $this->environment('KEYCLOAK_REDIRECT_URI', 'https://app.example.com/auth/callback');
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->compile(true);

        $config = $container->get(KeycloakConfiguration::class);

        $this->assertSame('https://auth.example.com/realms/derafu', $config->getIssuer());
        $this->assertSame('app', $config->getClientId());
        // What the environment does not say is the default, and the defaults are
        // the safe ones: the certificate is verified and the session of Keycloak
        // ends at the logout.
        $this->assertTrue($config->getHttpClientOptions()['verify']);
        $this->assertTrue($config->isEndSession());
        $this->assertSame('https://app.example.com/', $config->getPostLogoutRedirectUri());
    }

    #[Test]
    public function theEnvironmentCanChangeTheLogoutOfKeycloakAndTheIssuer(): void
    {
        $this->environment('KEYCLOAK_END_SESSION', 'false');
        $this->environment('KEYCLOAK_ISSUER', 'https://public.example.com/realms/derafu');
        $this->environment('KEYCLOAK_POST_LOGOUT_REDIRECT_URI', 'https://app.example.com/goodbye');
        $this->environment('KEYCLOAK_HTTP_VERIFY', 'false');
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->compile(true);

        $config = $container->get(KeycloakConfiguration::class);

        $this->assertFalse($config->isEndSession());
        $this->assertSame('https://public.example.com/realms/derafu', $config->getIssuer());
        $this->assertSame('https://app.example.com/goodbye', $config->getPostLogoutRedirectUri());
        $this->assertFalse($config->getHttpClientOptions()['verify']);
    }

    #[Test]
    public function theAuthenticationOfKeycloakIsTheOneThatMezzioGets(): void
    {
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(AuthenticationInterface::class)->setPublic(true);
        $container->compile(true);

        $this->assertInstanceOf(KeycloakAuthentication::class, $container->get(AuthenticationInterface::class));
    }

    #[Test]
    public function theLoginsOfTheDatabaseProviderAreLimitedByDefault(): void
    {
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(LoginThrottle::class)->setPublic(true);
        $container->getDefinition(AuthenticationInterface::class)->setPublic(true);
        $container->compile(true);

        $throttle = $container->get(LoginThrottle::class);
        $this->assertSame(5, $this->property($throttle, 'maxAttempts'));
        $this->assertSame(900, $this->property($throttle, 'lockSeconds'));

        // The authentication has it.
        $authentication = $container->get(AuthenticationInterface::class);
        $this->assertInstanceOf(DatabaseAuthentication::class, $authentication);
        $this->assertSame($throttle, $this->property($authentication, 'throttle'));
    }

    #[Test]
    public function theLimitOfTheLoginsIsTheOneOfTheEnvironment(): void
    {
        $this->environment('AUTH_LOGIN_MAX_ATTEMPTS', '2');
        $this->environment('AUTH_LOGIN_LOCK_SECONDS', '60');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(LoginThrottle::class)->setPublic(true);
        $container->compile(true);

        $throttle = $container->get(LoginThrottle::class);

        $this->assertSame(2, $this->property($throttle, 'maxAttempts'));
        $this->assertSame(60, $this->property($throttle, 'lockSeconds'));
    }

    #[Test]
    public function theRefreshIntervalOfKeycloakIsAutomaticUnlessTheEnvironmentSaysAnother(): void
    {
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertNull($container->get(KeycloakConfiguration::class)->getRefreshInterval());

        $this->environment('AUTH_REFRESH_INTERVAL', '90');
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertSame(90, $container->get(KeycloakConfiguration::class)->getRefreshInterval());
    }

    #[Test]
    public function theRefreshIntervalOfTheDatabaseIsTheDefaultUnlessTheEnvironmentSaysAnother(): void
    {
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertSame(300, $container->get(DatabaseConfiguration::class)->getRefreshInterval());

        $this->environment('AUTH_REFRESH_INTERVAL', '45');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertSame(45, $container->get(DatabaseConfiguration::class)->getRefreshInterval());
    }
}
