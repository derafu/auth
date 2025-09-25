<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Database;

use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Provider\Database\Form\LoginForm;
use Derafu\Renderer\Contract\RendererInterface;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Flash\FlashMessagesInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Database controller for the database provider of authentication.
 */
class DatabaseController
{
    /**
     * Creates a new database controller.
     *
     * @param RendererInterface $renderer The renderer.
     * @param FormManagerInterface $formManager The form manager.
     */
    public function __construct(
        private readonly RendererInterface $renderer,
        private readonly FormManagerInterface $formManager,
    ) {
    }

    /**
     * Renders the login page.
     *
     * This action does not process the form, it only renders the login page.
     * The processing of the form is done in the DatabaseAuthentication class.
     *
     * @param ServerRequestInterface $request The request.
     * @return string The rendered login page.
     */
    public function login(ServerRequestInterface $request): string
    {
        $form = $this->formManager->createForm(LoginForm::class, $request->getParsedBody());

        return $this->renderer->render('auth/login', [
            'form' => $form,
            'captchaSiteKey' => $this->formManager->getCaptchaSiteKey(),
            'flashMessages' => $this->getFlashMessages($request),
        ]);
    }

    /**
     * Gets the flash messages from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return FlashMessagesInterface The flash messages.
     */
    protected function getFlashMessages(
        ServerRequestInterface $request
    ): FlashMessagesInterface {
        return $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE);
    }
}
