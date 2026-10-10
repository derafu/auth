<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization Library.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak\Account\Form;

use Derafu\Auth\Contract\FormInterface;

/**
 * The form that makes a token of the API: the user gives its password again (and
 * the code of its second factor, if it has one).
 *
 * The titles are fixed texts, in English, in the domain `auth`: they are
 * translated when the form is created. The form is protected with a CSRF token,
 * as every form is by default.
 */
class ApiTokenForm implements FormInterface
{
    /**
     * The name of the field of the password.
     */
    public const PASSWORD = 'password';

    /**
     * The name of the field of the code of the second factor.
     */
    public const TOTP = 'totp';

    /**
     * The help of the password: what the field says about which password it asks
     * for. It is shown as it is (it is HTML), so what comes from the user is
     * escaped by whoever makes it.
     */
    private string $help = '';

    /**
     * The form with the help of the password.
     *
     * @param string $help The help, in the language of the user, as HTML.
     */
    public function withHelp(string $help): self
    {
        $form = clone $this;
        $form->help = $help;

        return $form;
    }

    /**
     * {@inheritDoc}
     */
    public function getDefinition(): array
    {
        $definition = $this->createDefinition();
        if ($this->help !== '') {
            $definition['schema']['properties'][self::PASSWORD]['description'] = $this->help;
        }

        return $definition;
    }

    /**
     * The definition, without what only the user knows.
     *
     * @return array<string, mixed>
     */
    private function createDefinition(): array
    {
        return [
            'options' => ['translation_domain' => 'auth'],
            'schema' => [
                'name' => 'api_token',
                'type' => 'object',
                'properties' => [
                    self::PASSWORD => [
                        'type' => 'string',
                        'title' => 'Password',
                        'minLength' => 1,
                    ],
                    self::TOTP => [
                        'type' => 'string',
                        'title' => 'Code of the second factor (if you use one)',
                    ],
                ],
                'required' => [self::PASSWORD],
            ],
            'uischema' => [
                'type' => 'VerticalLayout',
                'elements' => [
                    [
                        'type' => 'Control',
                        'scope' => '#/properties/' . self::PASSWORD,
                        'options' => [
                            'type' => 'password',
                            'input_group_prepend_icon' => 'fa-solid fa-lock',
                        ],
                    ],
                    [
                        'type' => 'Control',
                        'scope' => '#/properties/' . self::TOTP,
                        'options' => [
                            'input_group_prepend_icon' => 'fa-solid fa-key',
                        ],
                    ],
                ],
            ],
        ];
    }
}
