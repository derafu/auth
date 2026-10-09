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

use Derafu\Auth\Authentication\AuthenticationManager;
use Derafu\Auth\Authentication\AuthenticationMiddleware;
use Derafu\Auth\Authentication\Channel\Api\ApiChannel;
use Derafu\Auth\Authentication\Channel\Api\ApiConfiguration;
use Derafu\Auth\Authentication\Channel\Web\WebChannel;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Authentication\LoginThrottle;
use Derafu\Auth\Authorization\AccessRules;
use Derafu\Auth\Authorization\AuthorizationMiddleware;
use Derafu\Auth\Contract\AccessRulesInterface;
use Derafu\Auth\Contract\AuthenticationInterface as DerafuAuthenticationInterface;
use Derafu\Auth\Contract\ChannelInterface;
use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakTokenVerifier;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\UserFactory;
use Derafu\DataProcessor\ProcessorFactory;
use Derafu\Form\Contract\Factory\FormFactoryInterface;
use Derafu\Form\Contract\Processor\FormDataProcessorInterface;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Processor\FormDataProcessor;
use Derafu\Form\Processor\FormRulesResolver;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\CustomUserFactory;
use Derafu\TestsAuth\Fixture\GuestUser;
use Mezzio\Authentication\AuthenticationInterface;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Server\MiddlewareInterface;
use ReflectionProperty;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\VarExporter\LazyObjectInterface;

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

    /**
     * The object that a lazy service is: the services are lazy, so what the
     * container gives is a proxy of its interface until it is used.
     */
    private function real(object $object): object
    {
        return $object instanceof LazyObjectInterface ? $object->initializeLazyObject() : $object;
    }

    private function property(object $object, string $name): mixed
    {
        $object = $this->real($object);

        // The property of a class that the object extends (private there).
        $class = $object::class;
        while (!property_exists($class, $name)) {
            $class = get_parent_class($class) ?: throw new \LogicException('No property ' . $name);
        }

        return (new ReflectionProperty($class, $name))->getValue($object);
    }

    /**
     * The channels that the manager of the authentication asks, in order.
     *
     * @return list<ChannelInterface>
     */
    private function channels(ContainerBuilder $container): array
    {
        $manager = $container->get(DerafuAuthenticationInterface::class);

        return [...$this->property($manager, 'channels')];
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
        $this->environment('AUTH_KEYCLOAK_URL', 'https://auth.example.com');
        $this->environment('AUTH_KEYCLOAK_REALM', 'derafu');
        $this->environment('AUTH_KEYCLOAK_CLIENT_ID', 'app');
        $this->environment('AUTH_KEYCLOAK_CLIENT_SECRET', 'secret');
        $this->environment('AUTH_KEYCLOAK_WEB_REDIRECT_URI', 'https://app.example.com/auth/callback');
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->compile(true);

        $config = $container->get(KeycloakConfiguration::class);

        $this->assertSame('https://auth.example.com/realms/derafu', $config->getIssuer());
        $this->assertSame('app', $config->getClientId());
        $this->assertSame('https://app.example.com/auth/callback', $config->getRedirectUri());
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
        $this->environment('AUTH_KEYCLOAK_WEB_END_SESSION', 'false');
        $this->environment('AUTH_KEYCLOAK_ISSUER', 'https://public.example.com/realms/derafu');
        $this->environment('AUTH_KEYCLOAK_WEB_POST_LOGOUT_REDIRECT_URI', 'https://app.example.com/goodbye');
        $this->environment('AUTH_KEYCLOAK_HTTP_VERIFY', 'false');
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
    public function theAuthenticationThatMezzioGetsIsTheManagerOfEveryProvider(): void
    {
        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $services) {
            $container = $this->container($services, true);
            $container->getAlias(AuthenticationInterface::class)->setPublic(true);
            $container->compile(true);

            $authentication = $container->get(AuthenticationInterface::class);

            $this->assertInstanceOf(DerafuAuthenticationInterface::class, $authentication, $services);
            $this->assertInstanceOf(AuthenticationManager::class, $this->real($authentication), $services);
        }
    }

    #[Test]
    public function theChannelsAreAskedTheApiOneFirstAndTheWebOneLast(): void
    {
        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $services) {
            $container = $this->container($services, true);
            $container->getDefinition(DerafuAuthenticationInterface::class)->setPublic(true);
            $container->compile(true);

            $channels = $this->channels($container);

            $this->assertCount(2, $channels, $services);
            $this->assertSame(['api', 'web'], array_map(fn (ChannelInterface $channel) => $channel->name(), $channels), $services);
            $this->assertInstanceOf(ApiChannel::class, $this->real($channels[0]), $services);
            $this->assertInstanceOf(WebChannel::class, $this->real($channels[1]), $services);
        }
    }

    #[Test]
    public function aChannelThatTheApplicationTagsIsAskedInItsPriority(): void
    {
        $container = $this->container('auth-database-services.yaml', true);
        $container->register('app.channel', ApiChannel::class)
            ->setArguments([new Definition(ApiConfiguration::class, [['paths' => ['/hooks']]]), new Definition(\Derafu\Auth\Provider\Database\Api\DatabaseBasicScheme::class, [
                new Definition(DatabaseUserRepository::class, [new Definition(DatabaseConfiguration::class, [[]])]),
                new Definition(DatabaseConfiguration::class, [[]]),
            ])])
            ->addTag('derafu_auth.channel', ['priority' => 50]);
        $container->getDefinition(DerafuAuthenticationInterface::class)->setPublic(true);
        $container->compile(true);

        // Between the API one (100) and the web one (0).
        $this->assertCount(3, $this->channels($container));
        $this->assertSame('web', $this->channels($container)[2]->name());
    }

    #[Test]
    public function theLoginsOfTheDatabaseProviderAreLimitedByDefault(): void
    {
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(LoginThrottle::class)->setPublic(true);
        $container->getDefinition(DerafuAuthenticationInterface::class)->setPublic(true);
        $container->compile(true);

        $throttle = $container->get(LoginThrottle::class);
        $this->assertSame(5, $this->property($throttle, 'maxAttempts'));
        $this->assertSame(900, $this->property($throttle, 'lockSeconds'));

        // The form of the web and the scheme of the API have it.
        [$api, $web] = $this->channels($container);
        $this->assertSame($throttle, $this->real($this->property($this->property($web, 'flow'), 'throttle')));
        $this->assertSame($throttle, $this->real($this->property($this->property($api, 'scheme'), 'throttle')));
    }

    #[Test]
    public function theLimitOfTheLoginsIsTheOneOfTheEnvironment(): void
    {
        $this->environment('AUTH_DATABASE_LOGIN_MAX_ATTEMPTS', '2');
        $this->environment('AUTH_DATABASE_LOGIN_LOCK_SECONDS', '60');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(LoginThrottle::class)->setPublic(true);
        $container->compile(true);

        $throttle = $container->get(LoginThrottle::class);

        $this->assertSame(2, $this->property($throttle, 'maxAttempts'));
        $this->assertSame(60, $this->property($throttle, 'lockSeconds'));
    }

    #[Test]
    public function theRefreshIntervalIsAutomaticUnlessTheEnvironmentSaysAnother(): void
    {
        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $services) {
            $container = $this->container($services, true);
            $container->getDefinition(WebConfiguration::class)->setPublic(true);
            $container->compile(true);
            // The provider decides (the expiration of a token, or five minutes).
            $this->assertNull($container->get(WebConfiguration::class)->getRefreshInterval(), $services);

            $this->environment('AUTH_WEB_REFRESH_INTERVAL_SECONDS', '90');
            $container = $this->container($services, true);
            $container->getDefinition(WebConfiguration::class)->setPublic(true);
            $container->compile(true);
            $this->assertSame(90, $container->get(WebConfiguration::class)->getRefreshInterval(), $services);
            putenv('AUTH_WEB_REFRESH_INTERVAL_SECONDS');
        }
    }

    #[Test]
    public function theColumnAndTheQueryOfActiveUsersAreTheOnesOfTheEnvironment(): void
    {
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);
        $repository = $container->get(DatabaseConfiguration::class)->getUserRepository();
        $this->assertSame('active', $repository['field']['active']);
        $this->assertSame('SELECT active FROM user WHERE email = :identity', $repository['sql_is_active']);

        $this->environment('AUTH_DATABASE_USER_FIELD_ACTIVE', 'enabled');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertSame(
            'SELECT enabled FROM user WHERE email = :identity',
            $container->get(DatabaseConfiguration::class)->getUserRepository()['sql_is_active']
        );

        $this->environment('AUTH_DATABASE_USER_SQL_IS_ACTIVE', 'false');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertNull($container->get(DatabaseConfiguration::class)->getUserRepository()['sql_is_active']);
    }

    #[Test]
    public function theFactoryOfUsersIsTheDefaultOneUnlessTheApplicationReplacesIt(): void
    {
        foreach (['auth-database-services.yaml', 'auth-keycloak-services.yaml'] as $services) {
            $container = $this->container($services, true);
            $container->getAlias(UserFactoryInterface::class)->setPublic(true);
            $container->compile(true);

            $this->assertSame(UserFactory::class, $container->get(UserFactoryInterface::class)::class, $services);
        }
    }

    #[Test]
    public function aFactoryOfTheApplicationIsTheOneThatBothProvidersUse(): void
    {
        $database = $this->container('auth-database-services.yaml', true);
        $database->register(UserFactoryInterface::class, CustomUserFactory::class);
        $database->getDefinition(DatabaseUserRepository::class)->setPublic(true);
        $database->getDefinition(DerafuAuthenticationInterface::class)->setPublic(true);
        $database->compile(true);

        $this->assertInstanceOf(CustomUserFactory::class, $this->property($database->get(DatabaseUserRepository::class), 'userFactory'));
        $web = $this->channels($database)[1];
        $this->assertInstanceOf(CustomUserFactory::class, $this->property($this->property($web, 'flow'), 'userFactory'));

        $keycloak = $this->container('auth-keycloak-services.yaml', true);
        $keycloak->register(UserFactoryInterface::class, CustomUserFactory::class);
        $keycloak->getDefinition(KeycloakUserRepository::class)->setPublic(true);
        $keycloak->compile(true);

        $this->assertInstanceOf(CustomUserFactory::class, $this->property($keycloak->get(KeycloakUserRepository::class), 'userFactory'));
    }

    #[Test]
    public function theDatabaseOfTheProviderIsTheOneOfTheApplicationUnlessItHasItsOwn(): void
    {
        // Neither is set: there is no URL (the configuration says so when it is
        // used).
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertSame('', $container->get(DatabaseConfiguration::class)->getDatabaseUrl());

        // The one of the application.
        $this->environment('DATABASE_URL', 'sqlite:/data/application.db');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertSame('sqlite:/data/application.db', $container->get(DatabaseConfiguration::class)->getDatabaseUrl());

        // Its own, that comes first.
        $this->environment('AUTH_DATABASE_URL', 'sqlite:/data/users.db');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);
        $this->assertSame('sqlite:/data/users.db', $container->get(DatabaseConfiguration::class)->getDatabaseUrl());
    }

    #[Test]
    public function theVariablesOfKeycloakHaveTheNameOfTheirProviderTheirChannelAndTheUnitOfTheirNumbers(): void
    {
        $this->environment('AUTH_KEYCLOAK_HTTP_TIMEOUT_SECONDS', '7');
        $this->environment('AUTH_KEYCLOAK_HTTP_CONNECT_TIMEOUT_SECONDS', '3');
        $this->environment('AUTH_KEYCLOAK_WEB_CALLBACK_PATH', '/login/keycloak');
        $this->environment('AUTH_KEYCLOAK_WEB_SCOPES', '["openid", "email"]');
        $this->environment('AUTH_WEB_LOGIN_REDIRECT_PATH', '/dashboard');
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->getDefinition(WebConfiguration::class)->setPublic(true);
        $container->compile(true);
        $config = $container->get(KeycloakConfiguration::class);

        $this->assertSame(7, $config->getHttpClientOptions()['timeout']);
        $this->assertSame(3, $config->getHttpClientOptions()['connect_timeout']);
        $this->assertSame('/login/keycloak', $config->getCallbackPath());
        $this->assertSame(['openid', 'email'], $config->getScopes());
        $this->assertSame('/dashboard', $container->get(WebConfiguration::class)->getLoginRedirectPath());
    }

    #[Test]
    public function theVariablesOfTheWebChannelAreTheSameInEveryProviderWithTheDefaultsOfEach(): void
    {
        $this->environment('AUTH_WEB_LOGOUT_PATH', '/signout');
        $this->environment('AUTH_WEB_LOGOUT_REDIRECT_PATH', '/bye');
        $this->environment('AUTH_WEB_UNAUTHORIZED_REDIRECT_PATH', '/denied');

        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $services) {
            $container = $this->container($services, true);
            $container->getDefinition(WebConfiguration::class)->setPublic(true);
            $container->compile(true);
            $web = $container->get(WebConfiguration::class);

            $this->assertSame('/signout', $web->getLogoutPath(), $services);
            $this->assertSame('/bye', $web->getLogoutRedirectPath(), $services);
            $this->assertSame('/denied', $web->getUnauthorizedRedirectPath(), $services);
        }
    }

    #[Test]
    public function theLoginIsAPageOfTheSiteInTheDatabaseAndHtpasswdProvidersAndNotInKeycloak(): void
    {
        $expected = [
            'auth-keycloak-services.yaml' => ['/', '/'],
            'auth-database-services.yaml' => ['/auth/login', '/auth/login'],
            'auth-htpasswd-services.yaml' => ['/auth/login', '/auth/login'],
        ];

        foreach ($expected as $services => [$logoutRedirect, $unauthorizedRedirect]) {
            $container = $this->container($services, true);
            $container->getDefinition(WebConfiguration::class)->setPublic(true);
            $container->compile(true);
            $web = $container->get(WebConfiguration::class);

            $this->assertSame('/', $web->getLoginRedirectPath(), $services);
            $this->assertSame($logoutRedirect, $web->getLogoutRedirectPath(), $services);
            $this->assertSame($unauthorizedRedirect, $web->getUnauthorizedRedirectPath(), $services);
        }
    }

    #[Test]
    public function theVariablesOfTheDatabaseProviderAreTheOnesOfItsFile(): void
    {
        $this->environment('AUTH_DATABASE_USER_TABLE', 'people');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(DatabaseConfiguration::class)->setPublic(true);
        $container->compile(true);

        $this->assertSame('people', $container->get(DatabaseConfiguration::class)->getUserRepository()['table']);
    }

    #[Test]
    public function theHtpasswdProviderIsWiredWithTheVariablesOfItsFile(): void
    {
        $this->environment('AUTH_HTPASSWD_PATH', '%kernel.project_dir%/var/.htpasswd');
        $this->environment('AUTH_HTPASSWD_LOGIN_MAX_ATTEMPTS', '3');
        $this->environment('AUTH_HTPASSWD_LOGIN_LOCK_SECONDS', '120');
        $container = $this->container('auth-htpasswd-services.yaml', true);
        $container->getDefinition(HtpasswdConfiguration::class)->setPublic(true);
        $container->getDefinition(LoginThrottle::class)->setPublic(true);
        $container->getDefinition(DerafuAuthenticationInterface::class)->setPublic(true);
        $container->compile(true);

        $this->assertSame(dirname(__DIR__, 2) . '/var/.htpasswd', $container->get(HtpasswdConfiguration::class)->getHtpasswdPath());

        $throttle = $container->get(LoginThrottle::class);
        $this->assertSame(3, $this->property($throttle, 'maxAttempts'));
        $this->assertSame(120, $this->property($throttle, 'lockSeconds'));

        [$api, $web] = $this->channels($container);
        $this->assertSame($throttle, $this->real($this->property($this->property($web, 'flow'), 'throttle')));
        $this->assertSame($throttle, $this->real($this->property($this->property($api, 'scheme'), 'throttle')));
    }

    #[Test]
    public function theApiIsConfiguredWithTheSameVariablesInEveryProvider(): void
    {
        $this->environment('AUTH_API_PATHS', '["/api", "/docs/index.json"]');
        $this->environment('AUTH_API_REALM', 'Billing');

        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $file) {
            $container = $this->container($file, true);
            $container->getDefinition(ApiConfiguration::class)->setPublic(true);
            $container->compile(true);
            $config = $container->get(ApiConfiguration::class);

            $this->assertSame(['/api', '/docs/index.json'], $config->getPaths(), $file);
            $this->assertSame('Billing', $config->getRealm(), $file);
        }
    }

    #[Test]
    public function theApiIsTheOneOfApiWithTheRealmApiWhenTheEnvironmentDoesNotSayOtherwise(): void
    {
        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $file) {
            $container = $this->container($file, true);
            $container->getDefinition(ApiConfiguration::class)->setPublic(true);
            $container->compile(true);
            $config = $container->get(ApiConfiguration::class);

            $this->assertSame(['/api'], $config->getPaths(), $file);
            $this->assertSame('API', $config->getRealm(), $file);
        }
    }

    #[Test]
    public function theAccessRulesAreTheOnesOfTheEnvironmentInEveryProvider(): void
    {
        $this->environment('AUTH_PROTECTED_PATHS', '{"/dashboard": [], "/admin": ["admin"]}');

        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $file) {
            $container = $this->container($file, true);
            $container->getDefinition(AccessRulesInterface::class)->setPublic(true);
            $container->compile(true);
            $rules = $container->get(AccessRulesInterface::class);

            $this->assertInstanceOf(AccessRules::class, $this->real($rules), $file);
            $this->assertTrue($rules->isEnabled(), $file);
            $this->assertSame(['/dashboard' => [], '/admin' => ['admin']], $rules->getProtectedPaths(), $file);
        }

        // Turned off, for development and for tests.
        $this->environment('AUTH_ENABLED', 'false');
        $container = $this->container('auth-database-services.yaml', true);
        $container->getDefinition(AccessRulesInterface::class)->setPublic(true);
        $container->compile(true);
        $this->assertFalse($container->get(AccessRulesInterface::class)->isEnabled());
    }

    #[Test]
    public function theTokensOfTheApiAreAskedToKeycloakUnlessTheEnvironmentSaysNot(): void
    {
        $this->environment('AUTH_KEYCLOAK_CLIENT_ID', 'derafu-api');

        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->compile(true);
        $config = $container->get(KeycloakConfiguration::class);

        $this->assertTrue($config->isApiIntrospection());
        $this->assertSame('derafu-api', $config->getApiAudience(), 'The client of the application, if the audience is not given.');

        // Turned off: another audience is possible, as nobody asks Keycloak.
        $this->environment('AUTH_KEYCLOAK_API_INTROSPECTION', 'false');
        $this->environment('AUTH_KEYCLOAK_API_AUDIENCE', 'billing-api');
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->compile(true);
        $config = $container->get(KeycloakConfiguration::class);

        $this->assertFalse($config->isApiIntrospection());
        $this->assertSame('billing-api', $config->getApiAudience());

        // The client of the API, apart from the one of the login.
        $this->environment('AUTH_KEYCLOAK_API_AUDIENCE', '');
        $this->environment('AUTH_KEYCLOAK_API_INTROSPECTION', 'true');
        $this->environment('AUTH_KEYCLOAK_API_CLIENT_ID', 'billing-api');
        $this->environment('AUTH_KEYCLOAK_API_CLIENT_SECRET', 'billing-secret');
        $container = $this->container('auth-keycloak-services.yaml', true);
        $container->getDefinition(KeycloakConfiguration::class)->setPublic(true);
        $container->compile(true);
        $config = $container->get(KeycloakConfiguration::class);

        $this->assertSame('billing-api', $config->getApiClientId());
        $this->assertSame('billing-secret', $config->getApiClientSecret());
        $this->assertSame('billing-api', $config->getApiAudience());
    }

    #[Test]
    public function anAnonymousUserOfTheApplicationIsTheOneThatEveryPieceUses(): void
    {
        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $services) {
            $container = $this->container($services, true);
            $container->register(UserInterface::class, GuestUser::class);
            $container->getDefinition(DerafuAuthenticationInterface::class)->setPublic(true);
            $container->compile(true);

            $manager = $container->get(DerafuAuthenticationInterface::class);
            [$api, $web] = $this->channels($container);

            $this->assertInstanceOf(GuestUser::class, $this->property($manager, 'anonymousUser'), $services);
            $this->assertInstanceOf(GuestUser::class, $this->property($api, 'anonymousUser'), $services);
            $this->assertInstanceOf(GuestUser::class, $this->property($web, 'anonymousUser'), $services);
            $this->assertInstanceOf(GuestUser::class, $this->property($this->property($web, 'flow'), 'anonymousUser'), $services);
        }
    }

    #[Test]
    public function theMiddlewaresOfAPipelineAreTheOnesOfThePackageInEveryProvider(): void
    {
        foreach (['auth-keycloak-services.yaml', 'auth-database-services.yaml', 'auth-htpasswd-services.yaml'] as $services) {
            $container = $this->container($services, true);
            $container->getDefinition(AuthenticationMiddleware::class)->setPublic(true);
            $container->getDefinition(AuthorizationMiddleware::class)->setPublic(true);
            $container->compile(true);

            $this->assertInstanceOf(MiddlewareInterface::class, $container->get(AuthenticationMiddleware::class), $services);
            $this->assertInstanceOf(MiddlewareInterface::class, $container->get(AuthorizationMiddleware::class), $services);
            $this->assertInstanceOf(AuthenticationMiddleware::class, $this->real($container->get(AuthenticationMiddleware::class)), $services);
            $this->assertInstanceOf(AuthorizationMiddleware::class, $this->real($container->get(AuthorizationMiddleware::class)), $services);
            // The ones of Mezzio are not the ones of the pipeline.
            $this->assertFalse($container->has('Mezzio\\Authentication\\AuthenticationMiddleware'), $services);
            $this->assertFalse($container->has('Mezzio\\Authorization\\AuthorizationMiddleware'), $services);
        }
    }
}
