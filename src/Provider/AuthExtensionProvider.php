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

use Derafu\Auth\Contract\WebConfigurationInterface;
use Derafu\Auth\Twig\AuthExtension;
use Derafu\Twig\Contract\ExtensionProviderInterface;

final class AuthExtensionProvider implements ExtensionProviderInterface
{
    public function __construct(private readonly WebConfigurationInterface $configuration)
    {
    }

    public function getExtensions(array $options = []): iterable
    {
        yield new AuthExtension($this->configuration);
    }
}
