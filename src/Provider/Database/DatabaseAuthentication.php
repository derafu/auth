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

use Derafu\Auth\Abstract\AbstractProviderAuthentication;
use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\FormException;
use Derafu\Auth\Provider\Database\Form\LoginForm;
use Derafu\Auth\User;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Database authentication implementation for Mezzio.
 *
 * This class implements our AuthenticationInterface to provide
 * username/password authentication through database.
 */
class DatabaseAuthentication extends AbstractProviderAuthentication implements AuthenticationInterface
{
    /**
     * Creates a new Database authentication implementation.
     *
     * @param DatabaseUserRepository $userRepository The user repository.
     * @param DatabaseConfiguration $config The configuration.
     * @param SessionManagerInterface $sessionManager The session manager.
     * @param UserInterface $anonymousUser The anonymous user.
     */
    public function __construct(
        private readonly DatabaseUserRepository $userRepository,
        private readonly DatabaseConfiguration $config,
        private readonly SessionManagerInterface $sessionManager,
        private readonly FormManagerInterface $formManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser()
    ) {
        parent::__construct(
            config: $config,
            sessionManager: $sessionManager,
            anonymousUser: $anonymousUser
        );
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request): ?UserInterface
    {
        // Get the path, session and user from the request.
        $path = $request->getUri()->getPath();
        $session = $this->getSessionFromRequest($request);
        $user = $this->getUserFromSession($session);

        // Handle logout.
        if ($this->isLogoutPath($path)) {
            if ($session) {
                $this->logout($session);
            }
            // Must be null to trigger unauthorized response and handle logout.
            return null;
        }

        // Handle login.
        if ($this->isLoginPath($path) && $session) {
            $user = $this->handleLogin($request, $session) ?? $this->anonymousUser;
        }

        // If the path is not protected, return the user (authenticated or
        // anonymous).
        if (!$this->config->requiresAuth($path)) {
            return $user;
        }

        // If the path is protected, the user must be authenticated.
        if ($user->isAnonymous()) {
            // Must be null to trigger unauthorized response and give an error
            // message.
            return null;
        }

        // The user is authenticated, is not the logout path and is not the
        // login path, so return the user.
        return $user;
    }

    /**
     * {@inheritDoc}
     */
    protected function handleLogin(
        ServerRequestInterface $request,
        SessionInterface $session
    ): ?UserInterface {
        // Check if it's a POST request.
        if ($request->getMethod() !== 'POST') {
            return null;
        }

        // Get the form and process it.
        try {
            $result = $this->formManager->processForm(
                LoginForm::class,
                $request->getParsedBody()
            );
        } catch (FormException $e) {
            $this->addErrorFlash($request, $e->getMessage(), true);
            return null;
        }

        // Get the identity and password.
        $data = $result->getProcessedData();
        $identity = $data[$this->config->getUserIdentityField()];
        $password = $data[$this->config->getUserPasswordField()];

        // Attempt authentication.
        $user = $this->userRepository->authenticate($identity, $password);
        if ($user === null) {
            $this->addErrorFlash($request, 'Invalid identity or password.', true);
            return null;
        }

        // Store user information in session.
        $userInfo = [
            'identity' => $user->getIdentity(),
            'roles' => iterator_to_array($user->getRoles()),
            'details' => $user->getDetails(),
        ];
        $this->sessionManager->storeUserInfo($session, $userInfo);

        // Add success flash message.
        $this->addSuccessFlash($request, 'Successfully logged in.');

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    protected function getAuthenticatedUserFromSession(SessionInterface $session): ?UserInterface
    {
        // Get user information from session.
        $userInfo = $this->sessionManager->getUserInfo($session);
        if (!$userInfo) {
            return null;
        }

        // Create user from session data.
        return new User(
            identity: $userInfo['identity'],
            roles: $userInfo['roles'] ?? [],
            details: $userInfo['details'] ?? []
        );
    }
}
