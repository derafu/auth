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

use Derafu\Auth\Contract\ApiConfigurationInterface;
use Derafu\Support\Url;

/**
 * Application-owned API settings independent of the package's implementation.
 */
final class ApplicationApiConfiguration implements ApiConfigurationInterface
{
    private const API_PATH = '/partner/api';

    /**
     * {@inheritDoc}
     */
    public function getPaths(): array
    {
        return [self::API_PATH];
    }

    /**
     * {@inheritDoc}
     */
    public function isApiPath(string $path): bool
    {
        return Url::pathStartsWith($path, self::API_PATH);
    }

    /**
     * {@inheritDoc}
     */
    public function getRealm(): string
    {
        return 'Partner API';
    }
}
