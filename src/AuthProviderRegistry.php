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
use Derafu\Auth\Contract\AuthProviderRegistryInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\WebConfigurationInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Symfony\Contracts\Service\ServiceProviderInterface;

/**
 * The provider that the application uses, chosen with `AUTH_PROVIDER`.
 *
 * It is the one that gives the pieces that depend on the provider (the contracts
 * `WebFlowInterface`, `SessionManagerInterface`, `ApiSchemeInterface` and
 * `AccountInterface` are made by it), so the services of
 * the package are the same for every provider and the application only says which
 * one. The providers are the services tagged `derafu_auth.provider`, and the
 * name is the one that each gives (`AuthProviderInterface::name()`).
 *
 * The variable is read when the first piece is asked, not when the container is
 * built: with it empty or wrong, only what needs the provider fails, with a
 * message that says what to set.
 */
final class AuthProviderRegistry implements AuthProviderRegistryInterface
{
    /**
     * Creates the registry without resolving any provider services.
     *
     * @param ServiceProviderInterface<mixed> $providers The provider services,
     * indexed by name. Returned services are validated when selected.
     * @param string|null $name The chosen one (`AUTH_PROVIDER`): null or empty
     * when the variable is not set.
     */
    public function __construct(
        private readonly ServiceProviderInterface $providers,
        private readonly ?string $name
    ) {
    }

    /**
     * {@inheritDoc}
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
        if (!$provider instanceof AuthProviderInterface) {
            throw new ConfigurationException([
                'The authentication provider "{name}" must implement {interface}; received {type}.',
                'name' => $this->name,
                'interface' => AuthProviderInterface::class,
                'type' => get_debug_type($provider),
            ]);
        }

        return $provider;
    }

    /**
     * {@inheritDoc}
     */
    public function webFlow(): WebFlowInterface
    {
        return $this->provider()->webFlow();
    }

    /**
     * {@inheritDoc}
     */
    public function sessionManager(): SessionManagerInterface
    {
        return $this->provider()->sessionManager();
    }

    /**
     * {@inheritDoc}
     */
    public function apiScheme(): ApiSchemeInterface
    {
        return $this->provider()->apiScheme();
    }

    /**
     * {@inheritDoc}
     */
    public function account(): AccountInterface
    {
        return $this->provider()->account();
    }

    /**
     * {@inheritDoc}
     */
    public function webConfiguration(array $config): WebConfigurationInterface
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
        return array_map('strval', array_keys($this->providers->getProvidedServices()));
    }
}
