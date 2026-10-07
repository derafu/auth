<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Htpasswd;

use Derafu\Auth\Abstract\AbstractProviderAuthentication;
use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\FormException;
use Derafu\Auth\LoginThrottle;
use Derafu\Auth\Provider\Htpasswd\Form\LoginForm;
use Derafu\Auth\UserFactory;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Htpasswd authentication implementation for Mezzio.
 *
 * This class implements our AuthenticationInterface to provide
 * username/password authentication against an `.htpasswd` file.
 */
class HtpasswdAuthentication extends AbstractProviderAuthentication implements AuthenticationInterface
{
    private readonly UserFactoryInterface $userFactory;

    /**
     * Creates a new htpasswd authentication implementation.
     *
     * @param HtpasswdUserRepository $userRepository The user repository.
     * @param HtpasswdConfiguration $config The configuration.
     * @param SessionManagerInterface $sessionManager The session manager.
     * @param UserInterface $anonymousUser The anonymous user.
     * @param TranslatorInterface|null $translator Translates the response of an
     * unauthenticated request to the API.
     * @param LoginThrottle|null $throttle Limits the failed attempts to log in.
     * Without it the attempts are not limited.
     * @param UserFactoryInterface|null $userFactory Makes the users (the one of
     * the login, the one of the session, the one of the check). The default one
     * makes a `User`.
     */
    public function __construct(
        private readonly HtpasswdUserRepository $userRepository,
        private readonly HtpasswdConfiguration $config,
        private readonly SessionManagerInterface $sessionManager,
        private readonly FormManagerInterface $formManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser(),
        ?TranslatorInterface $translator = null,
        private readonly ?LoginThrottle $throttle = null,
        ?UserFactoryInterface $userFactory = null
    ) {
        $this->userFactory = $userFactory ?? new UserFactory();
        parent::__construct(
            config: $config,
            sessionManager: $sessionManager,
            anonymousUser: $anonymousUser,
            translator: $translator
        );
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

        // Get the form and process it. A request without a body (it is null in
        // some PSR-7 implementations) is a form without data.
        $body = $request->getParsedBody();
        try {
            $result = $this->formManager->processForm(
                LoginForm::class,
                is_array($body) ? $body : []
            );
        } catch (FormException $e) {
            $this->addErrorFlash($request, $e->getTranslatableMessage(), now: true);
            return null;
        }

        // Get the identity and password.
        $data = $result->getProcessedData();
        $identity = $data[LoginForm::IDENTITY];
        $password = $data[LoginForm::PASSWORD];
        $address = (string) ($request->getServerParams()['REMOTE_ADDR'] ?? 'unknown');

        // Too many failed attempts: the credentials are not even checked, so a
        // password that is guessed in the window is of no use.
        $seconds = $this->throttle?->retryAfter($identity, $address) ?? 0;
        if ($seconds > 0) {
            $this->addErrorFlash(
                $request,
                'Too many failed login attempts. Try again in {minutes, plural, one {# minute} other {# minutes}}.',
                ['minutes' => (int) ceil($seconds / 60)],
                now: true
            );

            return null;
        }

        // Attempt authentication.
        $user = $this->userRepository->authenticate($identity, $password);
        if ($user === null) {
            $this->throttle?->hit($identity, $address);
            $this->addErrorFlash($request, 'Invalid identity or password.', now: true);

            return null;
        }

        $this->throttle?->clear($identity, $address);

        // Store user information in session.
        $userInfo = [
            'identity' => $user->getIdentity(),
        ];
        $this->sessionManager->storeUserInfo($session, $userInfo);

        // The identifier that the session had before the login must be of no
        // use after it (session fixation).
        $this->sessionManager->regenerate($session);

        // Add success flash message.
        $this->addSuccessFlash($request, 'Successfully logged in.');

        return $user;
    }

    /**
     * {@inheritDoc}
     *
     * The file is read again every `refresh_interval` seconds, by the identity
     * that the session has: a user that is not in the file anymore loses the
     * session.
     */
    protected function getAuthenticatedUserFromSession(SessionInterface $session): ?UserInterface
    {
        // Get user information from session.
        $userInfo = $this->sessionManager->getUserInfo($session);
        if (!$userInfo) {
            return null;
        }

        if ($this->sessionManager->isRefreshDue($session, $this->config->getRefreshInterval())) {
            $user = $this->userRepository->find($userInfo['identity']);

            if ($user === null) {
                $this->sessionManager->clearSession($session);

                return $this->anonymousUser;
            }

            $this->sessionManager->storeUserInfo($session, ['identity' => $user->getIdentity()]);

            return $user;
        }

        // Create user from session data.
        return $this->userFactory->create($userInfo['identity']);
    }
}
