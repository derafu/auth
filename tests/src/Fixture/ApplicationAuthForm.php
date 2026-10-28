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

use Derafu\Auth\Contract\FormInterface;

/** A consuming application's form with a constructor dependency resolved by DI. */
final class ApplicationAuthForm implements FormInterface
{
    /**
     * @param string $field The application's configurable field name.
     */
    public function __construct(private readonly string $field)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function getDefinition(): array
    {
        return [
            'schema' => [
                'type' => 'object',
                'properties' => [$this->field => ['type' => 'string']],
            ],
        ];
    }
}
