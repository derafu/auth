<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Htpasswd\Form;

use Derafu\Auth\Contract\FormInterface;

/**
 * Login form.
 *
 * This form is used to login a user with an `.htpasswd` file: the fields are
 * always `username` and `password`, and their titles are fixed texts, in
 * English, in the domain `auth`.
 */
class LoginForm implements FormInterface
{
    public const IDENTITY = 'username';

    public const PASSWORD = 'password';

    /**
     * The form definition.
     *
     * @var array
     */
    private array $definition;

    /**
     * {@inheritDoc}
     */
    public function getDefinition(): array
    {
        if (!isset($this->definition)) {
            $this->definition = $this->createDefinition();
        }

        return $this->definition;
    }

    /**
     * Creates the form definition.
     *
     * @return array The form definition.
     */
    private function createDefinition(): array
    {
        $identityField = self::IDENTITY;
        $passwordField = self::PASSWORD;

        return [
            'options' => ['translation_domain' => 'auth', 'captcha_protection' => true],
            'schema' => [
                'name' => 'login',
                'type' => 'object',
                'properties' => [
                    $identityField => [
                        'type' => 'string',
                        'title' => 'Username',
                        'minLength' => 1,
                    ],
                    $passwordField => [
                        'type' => 'string',
                        'title' => 'Password',
                        'minLength' => 1,
                    ],
                ],
                'required' => [
                    $identityField,
                    $passwordField,
                ],
            ],
            'uischema' => [
                'type' => 'VerticalLayout',
                'elements' => [
                    [
                        'type' => 'Control',
                        'scope' => '#/properties/' . $identityField,
                        'options' => [
                            'input_group_prepend_icon' => 'fa-solid fa-user',
                        ],
                    ],
                    [
                        'type' => 'Control',
                        'scope' => '#/properties/' . $passwordField,
                        'options' => [
                            'type' => 'password',
                            'input_group_prepend_icon' => 'fa-solid fa-lock',
                        ],
                    ],
                ],
            ],
        ];
    }
}
