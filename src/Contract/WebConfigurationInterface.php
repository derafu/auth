<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

interface WebConfigurationInterface
{
    public function getLoginPath(): string;

    public function getLogoutPath(): string;

    public function getLoginRedirectPath(): string;

    public function getLogoutRedirectPath(): string;

    public function getUnauthorizedRedirectPath(): string;

    public function getRefreshInterval(): ?int;
}
