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
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserInterface;
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
        UserInterface $anonymousUser = new AnonymousUser()
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
    protected function handleLogin(
        ServerRequestInterface $request,
        SessionInterface $session
    ): ?UserInterface {
        $body = $request->getParsedBody();

        // Check if it's a POST request with credentials.
        if ($request->getMethod() !== 'POST' || !is_array($body)) {
            return null;
        }
        $identity = $body[$this->config->getUserIdentityField()] ?? '';
        $password = $body[$this->config->getUserPasswordField()] ?? '';

        // Validate input.
        if (empty($identity) || empty($password)) {
            $this->addErrorFlash($request, 'Identity and password are required.');
            return null;
        }

        // Attempt authentication.
        $user = $this->userRepository->authenticate($identity, $password);
        if ($user === null) {
            $this->addErrorFlash($request, 'Invalid identity or password.');
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
