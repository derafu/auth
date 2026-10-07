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

use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Provider\Database\Form\LoginForm;
use Derafu\Renderer\Contract\RendererInterface;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Flash\FlashMessagesInterface;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
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
     * @param ConfigurationInterface $config The configuration.
     * @param SessionManagerInterface $sessionManager The session manager.
     */
    public function __construct(
        private readonly RendererInterface $renderer,
        private readonly FormManagerInterface $formManager,
        private readonly ConfigurationInterface $config,
        private readonly SessionManagerInterface $sessionManager,
    ) {
    }

    /**
     * Renders the login page.
     *
     * This action does not process the form, it only renders the login page.
     * The processing of the form is done in the DatabaseAuthentication class.
     *
     * @param ServerRequestInterface $request The request.
     * @return string|ResponseInterface The rendered login page, or the redirect
     * of a user that is logged in.
     */
    public function login(ServerRequestInterface $request): string|ResponseInterface
    {
        // A user that is logged in (it just logged in, or it is on the login page
        // while it is) goes where it was going, or to the page that follows the
        // login: the login is a POST, and after it comes a redirect, so a reload
        // does not send the form again.
        $user = $request->getAttribute(MezzioUserInterface::class);
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        if ($user instanceof UserInterface && !$user->isAnonymous() && $session instanceof SessionInterface) {
            $redirectUrl = $this->sessionManager->getRedirectUrl($session)
                ?: $this->config->getLoginRedirectRoute()
            ;
            $this->sessionManager->clearRedirectUrl($session);

            return new RedirectResponse($redirectUrl);
        }

        // A request without a body (it is null in some PSR-7 implementations) is a
        // form without data.
        $body = $request->getParsedBody();
        $form = $this->formManager->createForm(LoginForm::class, is_array($body) ? $body : []);

        return $this->renderer->render('auth/login', [
            'form' => $form,
            'app' => [
                'flashes' => $this->getFlashMessages($request)->getFlashes(),
            ],
        ]);
    }

    /**
     * Gets the flash messages from the request.
     *
     * @param ServerRequestInterface $request The request.
     * @return FlashMessagesInterface The flash messages.
     */
    /**
     * Handles the logout request that the authentication did not handle (it does
     * it before this, when it is on the pipeline): the user goes to the page
     * that follows the logout.
     *
     * @param ServerRequestInterface $request The request.
     * @return ResponseInterface The redirect.
     */
    public function logout(ServerRequestInterface $request): ResponseInterface
    {
        return new RedirectResponse($this->config->getLogoutRedirectRoute());
    }

    protected function getFlashMessages(
        ServerRequestInterface $request
    ): FlashMessagesInterface {
        return $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE);
    }
}
