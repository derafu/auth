<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\AuthenticationManager;
use Derafu\Auth\Authentication\Channel\Api\ApiChannel;
use Derafu\Auth\Authentication\Channel\Api\ApiConfiguration;
use Derafu\Auth\Authentication\Channel\Web\WebChannel;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Authentication\LoginThrottle;
use Derafu\Auth\Authorization\AccessRules;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Provider\Database\Api\DatabaseBasicScheme;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\Provider\Database\Web\DatabaseWebFlow;
use Derafu\Auth\Provider\Htpasswd\Api\HtpasswdBasicScheme;
use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;
use Derafu\Auth\Provider\Htpasswd\HtpasswdUserRepository;
use Derafu\Auth\Provider\Htpasswd\Web\HtpasswdWebFlow;
use Derafu\Auth\Provider\Keycloak\Api\KeycloakBearerScheme;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakWebFlow;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use WeakMap;

/**
 * What an application assembles from the pieces of the package: the access rules,
 * the web channel and the API channel with the flow and the scheme of a provider,
 * and the manager of the authentication that asks the channels.
 *
 * The tests give the settings of the three that are not of the provider (the
 * protected paths, the web and the API) in one array, with the keys of the
 * environment variables without their prefix, so a test says in one place how its
 * application is set. They go with the configuration of the provider that the
 * test builds (`databaseConfiguration()`, `htpasswdConfiguration()`,
 * `keycloakConfiguration()`, or the `config()` of the fixtures), which keeps them
 * for the builders of this class, so a test does not repeat them:
 *
 *   - Access: `protected_paths`, `enabled`.
 *   - Web: `login_path`, `logout_path`, `login_redirect_path`,
 *     `logout_redirect_path`, `unauthorized_redirect_path`, `refresh_interval`.
 *   - API: `api_paths`, `api_realm`.
 */
final class Stack
{
    /**
     * The keys of the settings of the API, and the key that its configuration
     * gives them.
     */
    private const API = ['api_paths' => 'paths', 'api_realm' => 'realm'];

    /**
     * The keys that are not of a provider.
     */
    private const SETTINGS = [
        'protected_paths', 'enabled',
        'login_path', 'logout_path', 'login_redirect_path', 'logout_redirect_path',
        'unauthorized_redirect_path', 'refresh_interval',
        'api_paths', 'api_realm',
    ];

    /**
     * The settings that go with each configuration of a provider.
     *
     * @var WeakMap<object, array<string, mixed>>|null
     */
    private static ?WeakMap $remembered = null;

    /**
     * The configuration of the database provider, and its settings.
     *
     * @param array<string, mixed> $combined The keys of the provider and the
     * settings.
     */
    public static function databaseConfiguration(array $combined): DatabaseConfiguration
    {
        return self::remember(new DatabaseConfiguration($combined), $combined);
    }

    /**
     * The configuration of the htpasswd provider, and its settings.
     *
     * @param array<string, mixed> $combined
     */
    public static function htpasswdConfiguration(array $combined): HtpasswdConfiguration
    {
        return self::remember(new HtpasswdConfiguration($combined), $combined);
    }

    /**
     * The configuration of the Keycloak provider, and its settings.
     *
     * @param array<string, mixed> $combined
     */
    public static function keycloakConfiguration(array $combined): KeycloakConfiguration
    {
        return self::remember(new KeycloakConfiguration($combined), $combined);
    }

    /**
     * Keeps the settings that go with a configuration of a provider.
     *
     * @template T of object
     * @param T $config
     * @param array<string, mixed> $combined
     * @return T
     */
    public static function remember(object $config, array $combined): object
    {
        self::$remembered ??= new WeakMap();
        self::$remembered[$config] = array_intersect_key($combined, array_flip(self::SETTINGS));

        return $config;
    }

    /**
     * The settings that go with a configuration of a provider.
     *
     * @return array<string, mixed>
     */
    public static function settingsOf(object $config): array
    {
        return self::$remembered[$config] ?? [];
    }

    /**
     * The configuration of the web channel of the settings that go with a
     * configuration of a provider.
     */
    public static function webOf(object $config): WebConfiguration
    {
        return self::web(self::settingsOf($config));
    }

    /**
     * The access rules of the settings that go with a configuration of a provider.
     */
    public static function accessOf(object $config): AccessRules
    {
        return self::access(self::settingsOf($config));
    }

    /**
     * The access rules of some settings.
     *
     * @param array<string, mixed> $settings
     */
    public static function access(array $settings = []): AccessRules
    {
        return new AccessRules($settings);
    }

    /**
     * The configuration of the web channel of some settings.
     *
     * @param array<string, mixed> $settings
     */
    public static function web(array $settings = []): WebConfiguration
    {
        return new WebConfiguration($settings);
    }

    /**
     * The configuration of the API channel of some settings.
     *
     * @param array<string, mixed> $settings
     */
    public static function api(array $settings = []): ApiConfiguration
    {
        $api = [];
        foreach (self::API as $from => $to) {
            if (array_key_exists($from, $settings)) {
                $api[$to] = $settings[$from];
            }
        }

        return new ApiConfiguration($api);
    }

    /**
     * The manager of the authentication with the web channel and the API channel
     * (asked first) of a provider.
     *
     * @param array<string, mixed> $settings
     */
    public static function manager(
        WebFlowInterface $flow,
        ApiSchemeInterface $scheme,
        SessionManagerInterface $sessionManager,
        UserInterface $anonymousUser = new AnonymousUser(),
        ?TranslatorInterface $translator = null,
        array $settings = []
    ): AuthenticationManager {
        return new AuthenticationManager(
            [
                new ApiChannel(self::api($settings), $scheme, $anonymousUser, $translator),
                new WebChannel($flow, self::web($settings), $sessionManager, $anonymousUser),
            ],
            self::access($settings),
            $anonymousUser
        );
    }

    /**
     * The authentication of the database provider.
     *
     * @param array<string, mixed> $settings
     */
    public static function database(
        DatabaseUserRepository $userRepository,
        DatabaseConfiguration $config,
        SessionManagerInterface $sessionManager,
        FormManagerInterface $formManager,
        UserInterface $anonymousUser = new AnonymousUser(),
        ?TranslatorInterface $translator = null,
        ?LoginThrottle $throttle = null,
        ?UserFactoryInterface $userFactory = null,
        array $settings = []
    ): AuthenticationManager {
        $settings += self::settingsOf($config);

        return self::manager(
            new DatabaseWebFlow(
                $userRepository,
                $config,
                self::web($settings),
                $sessionManager,
                $formManager,
                $anonymousUser,
                $throttle,
                $userFactory
            ),
            new DatabaseBasicScheme($userRepository, $config, $throttle),
            $sessionManager,
            $anonymousUser,
            $translator,
            $settings
        );
    }

    /**
     * The authentication of the htpasswd provider.
     *
     * @param array<string, mixed> $settings
     */
    public static function htpasswd(
        HtpasswdUserRepository $userRepository,
        HtpasswdConfiguration $config,
        SessionManagerInterface $sessionManager,
        FormManagerInterface $formManager,
        UserInterface $anonymousUser = new AnonymousUser(),
        ?TranslatorInterface $translator = null,
        ?LoginThrottle $throttle = null,
        ?UserFactoryInterface $userFactory = null,
        array $settings = []
    ): AuthenticationManager {
        $settings += self::settingsOf($config);

        return self::manager(
            new HtpasswdWebFlow(
                $userRepository,
                $config,
                self::web($settings),
                $sessionManager,
                $formManager,
                $anonymousUser,
                $throttle,
                $userFactory
            ),
            new HtpasswdBasicScheme($userRepository, $config, $throttle),
            $sessionManager,
            $anonymousUser,
            $translator,
            $settings
        );
    }

    /**
     * The authentication of the Keycloak provider.
     *
     * @param array<string, mixed> $settings
     */
    public static function keycloak(
        KeycloakUserRepository $userRepository,
        KeycloakConfiguration $config,
        KeycloakSessionManager $sessionManager,
        UserInterface $anonymousUser = new AnonymousUser(),
        ?TranslatorInterface $translator = null,
        array $settings = [],
        ?CacheItemPoolInterface $cache = null
    ): AuthenticationManager {
        $settings += self::settingsOf($config);

        return self::manager(
            new KeycloakWebFlow($userRepository, $config, self::web($settings), $sessionManager, $anonymousUser),
            new KeycloakBearerScheme($userRepository, $config, $cache),
            $sessionManager,
            $anonymousUser,
            $translator,
            $settings
        );
    }
}
