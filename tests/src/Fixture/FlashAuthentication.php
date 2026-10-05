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

use Derafu\Auth\Abstract\AbstractProviderAuthentication;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Translation\Contract\TranslatableMessageInterface;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An authentication that gives access to the flash messages that the abstract
 * one adds, to test them without a provider.
 */
final class FlashAuthentication extends AbstractProviderAuthentication
{
    /**
     * @param array<string, mixed> $parameters
     */
    public function error(
        ServerRequestInterface $request,
        string|TranslatableMessageInterface $message,
        array $parameters = [],
        bool $now = false
    ): void {
        $this->addErrorFlash($request, $message, $parameters, $now);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public function success(
        ServerRequestInterface $request,
        string|TranslatableMessageInterface $message,
        array $parameters = [],
        bool $now = false
    ): void {
        $this->addSuccessFlash($request, $message, $parameters, $now);
    }

    protected function handleLogin(
        ServerRequestInterface $request,
        SessionInterface $session
    ): ?UserInterface {
        return null;
    }

    protected function getAuthenticatedUserFromSession(SessionInterface $session): ?UserInterface
    {
        return null;
    }
}
