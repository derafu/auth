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

use Derafu\Twig\Contract\TemplatePathProviderInterface;

/**
 * Contributes this package's templates to the shared Twig template search paths.
 */
final class AuthTemplatePathProvider implements TemplatePathProviderInterface
{
    /**
     * {@inheritDoc}
     */
    public function getPaths(): array
    {
        return [dirname(__DIR__, 2) . '/resources/templates'];
    }
}
