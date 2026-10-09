<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Database\Web;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Channel\Web\Flash;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Authentication\LoginThrottle;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\UserFactoryInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Exception\FormException;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\DatabaseUserRepository;
use Derafu\Auth\Provider\Database\Web\Form\LoginForm;
use Derafu\Auth\UserFactory;
use Mezzio\Session\SessionInterface;
use PDOException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The web flow of a database: the user logs in with its identity and its
 * password, in a form, and the session keeps it.
 *
 * It is what the provider gives to the web channel (`WebChannel`), which does the
 * rest: the session, the page that is remembered, the redirects.
 */
class DatabaseWebFlow implements WebFlowInterface
{
    private readonly UserFactoryInterface $userFactory;

    /**
     * Creates the web flow.
     *
     * @param DatabaseUserRepository $userRepository The user repository.
     * @param DatabaseConfiguration $config The configuration of the provider.
     * @param WebConfiguration $web The configuration of the web channel.
     * @param SessionManagerInterface $sessionManager The session manager.
     * @param FormManagerInterface $formManager Makes and processes the login form.
     * @param UserInterface $anonymousUser The anonymous user.
     * @param LoginThrottle|null $throttle Limits the failed attempts to log in.
     * Without it the attempts are not limited.
     * @param UserFactoryInterface|null $userFactory Makes the users (the one of
     * the login, the one of the session, the one of the check). The default one
     * makes a `User`.
     */
    public function __construct(
        private readonly DatabaseUserRepository $userRepository,
        private readonly DatabaseConfiguration $config,
        private readonly WebConfiguration $web,
        private readonly SessionManagerInterface $sessionManager,
        private readonly FormManagerInterface $formManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser(),
        private readonly ?LoginThrottle $throttle = null,
        ?UserFactoryInterface $userFactory = null
    ) {
        $this->userFactory = $userFactory ?? new UserFactory();
    }

    /**
     * {@inheritDoc}
     */
    public function loginPath(): string
    {
        return $this->web->getLoginPath();
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        $this->config->validate();
    }

    /**
     * {@inheritDoc}
     */
    public function login(
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
            Flash::error($request, $e->getTranslatableMessage(), now: true);
            return null;
        }

        // Get the identity and password.
        $data = $result->getProcessedData();
        $identity = $data[$this->config->getUserIdentityField()];
        $password = $data[$this->config->getUserPasswordField()];
        $address = LoginThrottle::clientOf($request);

        // Too many failed attempts: the credentials are not even checked, so a
        // password that is guessed in the window is of no use.
        $seconds = $this->throttle?->retryAfter($identity, $address) ?? 0;
        if ($seconds > 0) {
            Flash::error(
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
            Flash::error($request, 'Invalid identity or password.', now: true);

            return null;
        }

        $this->throttle?->clear($identity, $address);

        // Store user information in session.
        $userInfo = [
            'identity' => $user->getIdentity(),
            'roles' => iterator_to_array($user->getRoles()),
            'details' => $user->getDetails(),
        ];
        $this->sessionManager->storeUserInfo($session, $userInfo);

        // The identifier that the session had before the login must be of no
        // use after it (session fixation).
        $this->sessionManager->regenerate($session);

        // Add success flash message.
        Flash::success($request, 'Successfully logged in.');

        return $user;
    }

    /**
     * {@inheritDoc}
     *
     * The user of the session is a copy of what the database said when the user
     * logged in, and the database is asked again every `refresh_interval`
     * seconds, by the identity that the session has: the roles and the details
     * are the ones of now, and a user that is not there anymore loses the
     * session. If the database can not be asked nothing is thrown away and the
     * user is not let in without being verified: the next request asks again.
     */
    public function userFromSession(SessionInterface $session): ?UserInterface
    {
        // Get user information from session.
        $userInfo = $this->sessionManager->getUserInfo($session);
        if (!$userInfo) {
            return null;
        }

        if ($this->sessionManager->isRefreshDue($session, $this->web->getRefreshInterval() ?? WebConfiguration::DEFAULT_REFRESH_INTERVAL)) {
            try {
                $user = $this->userRepository->find($userInfo['identity']);
            } catch (PDOException) {
                return null;
            }

            if ($user === null) {
                $this->sessionManager->clearSession($session);

                return $this->anonymousUser;
            }

            $this->sessionManager->storeUserInfo($session, [
                'identity' => $user->getIdentity(),
                'roles' => iterator_to_array($user->getRoles()),
                'details' => $user->getDetails(),
            ]);

            return $user;
        }

        // Create user from session data.
        return $this->userFactory->create(
            $userInfo['identity'],
            $userInfo['roles'] ?? [],
            $userInfo['details'] ?? []
        );
    }

    /**
     * {@inheritDoc}
     *
     * There is no session of the provider to end: the user goes to the page that
     * follows the logout.
     */
    public function logoutUrl(ServerRequestInterface $request, ?SessionInterface $session): ?string
    {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * The login is a page of the site: the user is sent there by the web channel.
     */
    public function loginRedirect(ServerRequestInterface $request, SessionInterface $session): ?ResponseInterface
    {
        return null;
    }
}
