<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth;

use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Contract\AccountInterface;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\AuthProviderInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Psr\Container\ContainerInterface;
use Symfony\Contracts\Service\ServiceProviderInterface;

/**
 * The provider that the application uses, chosen with `AUTH_PROVIDER`.
 *
 * It is the one that gives the pieces that depend on the provider (the contracts
 * `WebFlowInterface`, `SessionManagerInterface`, `FormManagerInterface`,
 * `ApiSchemeInterface` and `AccountInterface` are made by it), so the services of
 * the package are the same for every provider and the application only says which
 * one. The providers are the services tagged `derafu_auth.provider`, and the
 * name is the one that each gives (`AuthProviderInterface::name()`).
 *
 * The variable is read when the first piece is asked, not when the container is
 * built: with it empty or wrong, only what needs the provider fails, with a
 * message that says what to set.
 */
final class AuthProviderRegistry
{
    /**
     * @param ContainerInterface $providers The providers, by name.
     * @param string|null $name The chosen one (`AUTH_PROVIDER`): null or empty
     * when the variable is not set.
     */
    public function __construct(
        private readonly ContainerInterface $providers,
        private readonly ?string $name
    ) {
    }

    /**
     * The chosen provider.
     *
     * @throws ConfigurationException If there is none chosen, or it is not known.
     */
    public function provider(): AuthProviderInterface
    {
        $names = $this->names();
        if ($names === []) {
            throw new ConfigurationException(
                'There are no providers: tag the service of each one with derafu_auth.provider.'
            );
        }

        if ($this->name === null || $this->name === '') {
            throw new ConfigurationException([
                'AUTH_PROVIDER is not set. Choose one of: {providers}.',
                'providers' => implode(', ', $names),
            ]);
        }

        if (!$this->providers->has($this->name)) {
            throw new ConfigurationException([
                'AUTH_PROVIDER "{name}" is not a provider. Choose one of: {providers}.',
                'name' => $this->name,
                'providers' => implode(', ', $names),
            ]);
        }

        $provider = $this->providers->get($this->name);
        assert($provider instanceof AuthProviderInterface);

        return $provider;
    }

    public function webFlow(): WebFlowInterface
    {
        return $this->provider()->webFlow();
    }

    public function sessionManager(): SessionManagerInterface
    {
        return $this->provider()->sessionManager();
    }

    public function forms(): FormManagerInterface
    {
        return $this->provider()->forms();
    }

    public function apiScheme(): ApiSchemeInterface
    {
        return $this->provider()->apiScheme();
    }

    public function account(): AccountInterface
    {
        return $this->provider()->account();
    }

    /**
     * The configuration of the web channel: the paths that `$config` gives, and
     * for the ones it does not, what the provider asks for.
     *
     * @param array<string, mixed> $config See `WebConfiguration`.
     */
    public function webConfiguration(array $config): WebConfiguration
    {
        return new WebConfiguration($config, $this->webDefaults());
    }

    /**
     * The paths of the web channel that the provider asks for, or none if there
     * is no provider to ask: the paths are needed in pages that do not use the
     * provider, and the error of a provider that is not set is told where it is
     * used.
     *
     * @return array<string, string>
     */
    private function webDefaults(): array
    {
        try {
            return $this->provider()->webDefaults();
        } catch (ConfigurationException) {
            return [];
        }
    }

    /**
     * The names to choose from.
     *
     * @return list<string>
     */
    private function names(): array
    {
        return $this->providers instanceof ServiceProviderInterface
            ? array_map('strval', array_keys($this->providers->getProvidedServices()))
            : [];
    }
}
