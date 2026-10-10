<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider;

use Closure;
use Derafu\Auth\Contract\AccountInterface;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\AuthProviderInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\WebFlowInterface;

/**
 * Base of the providers: it holds the pieces that the provider gives, as
 * closures that make them when they are asked for.
 *
 * A closure and not the piece itself, so that choosing a provider does not make
 * the pieces of the others, and the container can have all of them defined
 * (`service_closure` in the services of the package).
 */
abstract class AuthProvider implements AuthProviderInterface
{
    /**
     * @param Closure(): WebFlowInterface $webFlow
     * @param Closure(): SessionManagerInterface $sessionManager
     * @param Closure(): FormManagerInterface $forms
     * @param Closure(): ApiSchemeInterface $apiScheme
     * @param Closure(): AccountInterface $account
     */
    public function __construct(
        private readonly Closure $webFlow,
        private readonly Closure $sessionManager,
        private readonly Closure $forms,
        private readonly Closure $apiScheme,
        private readonly Closure $account
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function webFlow(): WebFlowInterface
    {
        return ($this->webFlow)();
    }

    /**
     * {@inheritDoc}
     */
    public function sessionManager(): SessionManagerInterface
    {
        return ($this->sessionManager)();
    }

    /**
     * {@inheritDoc}
     */
    public function forms(): FormManagerInterface
    {
        return ($this->forms)();
    }

    /**
     * {@inheritDoc}
     */
    public function apiScheme(): ApiSchemeInterface
    {
        return ($this->apiScheme)();
    }

    /**
     * {@inheritDoc}
     */
    public function account(): AccountInterface
    {
        return ($this->account)();
    }

    /**
     * {@inheritDoc}
     *
     * None by default: the paths of the web channel are the ones of the package.
     */
    public function webDefaults(): array
    {
        return [];
    }
}
