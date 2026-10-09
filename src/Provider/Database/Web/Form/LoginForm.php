<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Database\Web\Form;

use Derafu\Auth\Contract\FormInterface;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;

/**
 * Login form.
 *
 * This form is used to login a user using a database.
 *
 * The names of its fields are the columns of the user table that are configured
 * (they are what `DatabaseAuthentication` reads), but their titles are fixed
 * texts, in English, in the domain `auth`: they are translated when the form is
 * created, and they do not depend on how the columns are named.
 */
class LoginForm implements FormInterface
{
    /**
     * The form definition.
     *
     * @var array
     */
    private array $definition;

    /**
     * Creates a new login form.
     *
     * @param DatabaseConfiguration $config The database configuration.
     */
    public function __construct(
        private readonly DatabaseConfiguration $config
    ) {
    }

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
        $identityField = $this->config->getUserIdentityField();
        $passwordField = $this->config->getUserPasswordField();

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
