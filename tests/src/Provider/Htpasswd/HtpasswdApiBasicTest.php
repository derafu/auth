<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Htpasswd;

use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\FormManager;
use Derafu\Auth\LoginThrottle;
use Derafu\Auth\Provider\Htpasswd\HtpasswdAuthentication;
use Derafu\Auth\Provider\Htpasswd\HtpasswdUserRepository;
use Derafu\Auth\SessionManager;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\HtpasswdFile;
use Derafu\TestsAuth\Fixture\SessionApp;
use Derafu\TestsAuth\Provider\ApiBasicTests;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * A client of the API that sends its user and its password to the provider of the
 * `.htpasswd` file.
 */
#[CoversClass(HtpasswdAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderAuthentication::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(\Derafu\Auth\AnonymousUser::class)]
#[UsesClass(\Derafu\Auth\Authorization::class)]
#[UsesClass(FormManager::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration::class)]
#[UsesClass(HtpasswdUserRepository::class)]
#[UsesClass(\Derafu\Auth\Provider\Htpasswd\Form\LoginForm::class)]
#[UsesClass(LoginThrottle::class)]
#[UsesClass(SessionManager::class)]
#[UsesClass(\Derafu\Auth\User::class)]
#[UsesClass(\Derafu\Auth\UserFactory::class)]
final class HtpasswdApiBasicTest extends TestCase
{
    use ApiBasicTests;

    private SessionApp $app;

    private HtpasswdFile $file;

    protected function setUp(): void
    {
        $this->app = new SessionApp();
        $this->file = new HtpasswdFile(['ana' => 'secret', 'beto' => 'other']);
    }

    protected function tearDown(): void
    {
        $this->file->remove();
    }

    protected function app(): SessionApp
    {
        return $this->app;
    }

    protected function identity(): string
    {
        return 'ana';
    }

    protected function basic(array $config = [], ?LoginThrottle $throttle = null): AuthenticationInterface
    {
        $config = $this->file->config($config + [
            'enabled' => true,
            'protected_paths' => ['/api', '/private'],
            'unauthorized_redirect_path' => '/auth/login',
        ]);

        return new HtpasswdAuthentication(
            new HtpasswdUserRepository($config),
            $config,
            new SessionManager(),
            new FormManager(
                new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
                $this->app->processor(),
                $config
            ),
            throttle: $throttle
        );
    }
}
