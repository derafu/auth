<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication\Channel\Web;

use Derafu\Auth\Contract\FormInterface as AuthFormInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Exception\FormException;
use Derafu\Form\Contract\Factory\FormFactoryInterface;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Contract\Processor\FormDataProcessorInterface;
use Derafu\Form\Contract\Processor\ProcessResultInterface;

/**
 * Form manager implementation.
 */
class FormManager implements FormManagerInterface
{
    /**
     * The form definitions.
     *
     * @var array<string, AuthFormInterface>
     */
    private array $forms = [];

    /**
     * Creates a new form manager.
     *
     * @param FormFactoryInterface $formFactory The form factory.
     * @param FormDataProcessorInterface $formDataProcessor The form data processor.
     * @param object $configuration The configuration of the provider, that the
     * forms are made with (the columns of the login form of a database, for
     * example).
     */
    public function __construct(
        private readonly FormFactoryInterface $formFactory,
        private readonly FormDataProcessorInterface $formDataProcessor,
        private readonly object $configuration,
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function createForm(
        string $formType,
        array $data = []
    ): FormInterface {
        $formDefinition = $this->getFormDefinition($formType);

        if (!empty($data)) {
            $formDefinition['data'] = $data;
        }

        return $this->formFactory->create($formDefinition);
    }

    /**
     * {@inheritDoc}
     */
    public function processForm(string $formType, array $data = []): ProcessResultInterface
    {
        $form = $this->createForm($formType);

        $result = $this->formDataProcessor->process($form, $data);

        if (!$result->isValid()) {
            // An error of the form as a whole (for example a CSRF token that is
            // not valid) says more than the generic message: the form already
            // has its text, translated if the processor has a translator.
            $formError = $result->getFormErrors()[0] ?? null;
            if ($formError !== null) {
                throw new FormException($formError, 400);
            }

            throw new FormException('Invalid form data.', 400);
        }

        return $result;
    }

    /**
     * Gets the form definition.
     *
     * @param class-string<AuthFormInterface> $formType The form type.
     * @return array The form definition.
     */
    private function getFormDefinition(string $formType): array
    {
        if (!isset($this->forms[$formType])) {
            $this->forms[$formType] = new $formType($this->configuration);
        }

        return $this->forms[$formType]->getDefinition();
    }
}
