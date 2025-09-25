<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth;

use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Contract\FormInterface as AuthFormInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Exception\FormException;
use Derafu\Form\Contract\Factory\FormFactoryInterface;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Contract\Processor\FormDataProcessorInterface;
use Derafu\Form\Contract\Processor\ProcessResultInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

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
     * Captcha site key.
     *
     * @var string|null
     */
    private ?string $captchaSiteKey = null;

    /**
     * Captcha secret key.
     *
     * @var string|null
     */
    private ?string $captchaSecretKey = null;

    /**
     * Creates a new form manager.
     *
     * @param FormFactoryInterface $formFactory The form factory.
     * @param FormDataProcessorInterface $formDataProcessor The form data processor.
     * @param ParameterBagInterface $parameterBag The parameter bag.
     */
    public function __construct(
        private readonly FormFactoryInterface $formFactory,
        private readonly FormDataProcessorInterface $formDataProcessor,
        private readonly ConfigurationInterface $configuration,
        ParameterBagInterface $parameterBag,
    ) {
        // Load the captcha configuration.
        if ($parameterBag->has('captcha.site_key') && $parameterBag->has('captcha.secret_key')) {
            $this->captchaSiteKey = $parameterBag->get('captcha.site_key');
            $this->captchaSecretKey = $parameterBag->get('captcha.secret_key');
        }
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
            throw new FormException('Invalid form data.', 400);
        }

        $this->validateCaptcha($result->getProcessedData());

        return $result;
    }

    /**
     * {@inheritDoc}
     */
    public function getCaptchaSiteKey(): ?string
    {
        return $this->captchaSiteKey;
    }

    /**
     * Validate the captcha.
     *
     * @param array $data
     * @return void
     * @throws FormException If the captcha is invalid.
     */
    private function validateCaptcha(array $data): void
    {
        // If the captcha is not configured, skip validation.
        if (!$this->captchaSiteKey || !$this->captchaSecretKey) {
            return;
        }

        // Validate the captcha.
        // TODO: Implement captcha validation and throw an exception if it fails.
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
