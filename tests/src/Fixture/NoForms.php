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

use Derafu\Auth\Contract\FormInterface as AuthFormInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Contract\Processor\ProcessResultInterface;
use LogicException;

/**
 * The forms of a provider that has none (Keycloak: the login is at its page): a
 * test that gets here used a form where there is not one.
 */
final class NoForms implements FormManagerInterface
{
    public function createForm(string|AuthFormInterface $form, array $data = []): FormInterface
    {
        throw new LogicException('This provider has no forms.');
    }

    public function processForm(string $formType, array $data = []): ProcessResultInterface
    {
        throw new LogicException('This provider has no forms.');
    }
}
