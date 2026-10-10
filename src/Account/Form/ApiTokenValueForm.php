<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization Library.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Account\Form;

use Derafu\Auth\Contract\FormInterface;

/**
 * The field that shows a token that was just made: hidden, like a password, with the
 * buttons to show it and to copy it (the ones of `derafu/form`, that work with
 * `derafu-js`). It is not sent anywhere, so it has no CSRF token.
 */
class ApiTokenValueForm implements FormInterface
{
    /**
     * The name of the field of the token.
     */
    public const TOKEN = 'token';

    /**
     * {@inheritDoc}
     */
    public function getDefinition(): array
    {
        return [
            'options' => ['translation_domain' => 'auth', 'csrf_protection' => false],
            'schema' => [
                'name' => 'api_token_value',
                'type' => 'object',
                'properties' => [
                    self::TOKEN => [
                        'type' => 'string',
                        'title' => 'Token',
                    ],
                ],
            ],
            'uischema' => [
                'type' => 'VerticalLayout',
                'elements' => [
                    [
                        'type' => 'Control',
                        'scope' => '#/properties/' . self::TOKEN,
                        'options' => [
                            'type' => 'password',
                            'readonly' => true,
                            'attr' => ['autocomplete' => 'off'],
                            'actions' => ['toggle-password', 'copy'],
                        ],
                    ],
                ],
            ],
        ];
    }
}
