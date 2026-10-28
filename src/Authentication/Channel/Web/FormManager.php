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
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Exception\FormException;
use Derafu\Form\Contract\Factory\FormFactoryInterface;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Contract\Processor\FormDataProcessorInterface;
use Derafu\Form\Contract\Processor\ProcessResultInterface;
use Psr\Container\ContainerInterface;

/**
 * Creates and processes forms from registered authentication definitions.
 *
 * Class names are resolved through a locator restricted to form definitions.
 * Definitions supplied as objects are used directly, including runtime context
 * added by the caller. Resolved definitions are cached by class name.
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
     * @param ContainerInterface $formDefinitions The lazy form definition locator,
     * indexed by form class name. Services must implement AuthFormInterface;
     * their actual types are validated when requested.
     */
    public function __construct(
        private readonly FormFactoryInterface $formFactory,
        private readonly FormDataProcessorInterface $formDataProcessor,
        private readonly ContainerInterface $formDefinitions,
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function createForm(
        string|AuthFormInterface $form,
        array $data = []
    ): FormInterface {
        $formDefinition = $form instanceof AuthFormInterface
            ? $form->getDefinition()
            : $this->getFormDefinition($form);

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
     * @return array<string, mixed> The form definition.
     * @throws ConfigurationException If the form is not registered or its service
     * does not implement the authentication form contract.
     */
    private function getFormDefinition(string $formType): array
    {
        if (!isset($this->forms[$formType])) {
            if (!$this->formDefinitions->has($formType)) {
                throw new ConfigurationException([
                    'The authentication form "{form}" is not registered. Register its service with the derafu_auth.form tag.',
                    'form' => $formType,
                ]);
            }

            $definition = $this->formDefinitions->get($formType);
            if (!$definition instanceof AuthFormInterface) {
                throw new ConfigurationException([
                    'The authentication form "{form}" must implement {interface}; received {type}.',
                    'form' => $formType,
                    'interface' => AuthFormInterface::class,
                    'type' => get_debug_type($definition),
                ]);
            }

            $this->forms[$formType] = $definition;
        }

        return $this->forms[$formType]->getDefinition();
    }
}
