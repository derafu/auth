<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Derafu\Auth\Contract\FormInterface as AuthFormInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Exception\FormException;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Contract\Processor\ProcessResultInterface;

/**
 * Form manager interface.
 *
 * Provides a consistent interface for all form manager classes across different
 * authentication and authorization providers.
 */
interface FormManagerInterface
{
    /**
     * Creates a new form instance.
     *
     * Class names identify definition services registered with derafu_auth.form.
     * An object definition is used directly and requires no locator registration.
     *
     * @param class-string<AuthFormInterface>|AuthFormInterface $form The form type,
     * or the form itself when it has what only the caller knows (the help of a
     * field that says which user it is for, for example).
     * @param array<array-key, mixed> $data The form data.
     * @return FormInterface The form instance.
     * @throws ConfigurationException If the requested definition service is missing
     * or does not implement AuthFormInterface.
     */
    public function createForm(string|AuthFormInterface $form, array $data = []): FormInterface;

    /**
     * Creates a form from its registered definition and processes submitted data.
     *
     * @param class-string<AuthFormInterface> $formType The form type.
     * @param array<array-key, mixed> $data The form data.
     * @return ProcessResultInterface The valid form result.
     * @throws ConfigurationException If the requested definition service is missing
     * or does not implement AuthFormInterface.
     * @throws FormException If form processing produces validation errors.
     */
    public function processForm(string $formType, array $data = []): ProcessResultInterface;
}
