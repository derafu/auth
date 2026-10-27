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

use Composer\InstalledVersions;
use Derafu\Form\Contract\Captcha\CaptchaProviderInterface;
use Derafu\Form\Contract\Csrf\CsrfTokenManagerInterface;
use LogicException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/** Loads the package YAML and the configuration of a consuming application. */
final class AuthApplication
{
    public static function container(): ContainerBuilder
    {
        $root = dirname(__DIR__, 3);
        $container = new ContainerBuilder();
        $container->setParameter('kernel.project_dir', $root);
        self::load($container, 'application.yaml');

        return $container;
    }

    public static function load(ContainerBuilder $container, string $fixture): void
    {
        $root = dirname(__DIR__, 3);
        (new YamlFileLoader($container, new FileLocator([
            $root . '/tests/fixtures/config',
            (InstalledVersions::getInstallPath('derafu/renderer')
                ?? throw new LogicException('derafu/renderer must be installed.')) . '/resources/config',
        ])))->load($fixture);
    }

    /**
     * @template T of object
     * @param class-string<T> $id
     * @return T
     */
    public static function service(
        string $id,
        ?CsrfTokenManagerInterface $csrf = null,
        ?CaptchaProviderInterface $captcha = null,
    ): object {
        $container = self::container();
        foreach ([CsrfTokenManagerInterface::class => $csrf, CaptchaProviderInterface::class => $captcha] as $contract => $service) {
            if ($service !== null) {
                $container->register($contract)->setSynthetic(true)->setPublic(true);
            }
        }
        $container->getDefinition($id)->setPublic(true);
        $container->compile(true);
        foreach ([CsrfTokenManagerInterface::class => $csrf, CaptchaProviderInterface::class => $captcha] as $contract => $service) {
            if ($service !== null) {
                $container->set($contract, $service);
            }
        }
        $service = $container->get($id);
        if (!$service instanceof $id) {
            throw new LogicException('The configured service has an unexpected type.');
        }

        return $service;
    }
}
