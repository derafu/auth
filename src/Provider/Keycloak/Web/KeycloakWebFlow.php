<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak\Web;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\Channel\Web\Flash;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Exception;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The web flow of Keycloak: OpenID Connect, the authorization code flow with
 * PKCE. The user is sent to Keycloak to log in, comes back to the callback with
 * a code, and the session keeps its tokens.
 *
 * It is what Keycloak gives to the web channel (`WebChannel`), which does the
 * rest: the session, the page that is remembered, the flash messages.
 */
class KeycloakWebFlow implements WebFlowInterface
{
    /**
     * Creates the web flow of Keycloak.
     *
     * @param KeycloakUserRepository $userRepository The user repository.
     * @param KeycloakConfiguration $config The configuration of Keycloak.
     * @param WebConfiguration $web The configuration of the web channel.
     * @param KeycloakSessionManager $sessionManager The session manager.
     * @param UserInterface $anonymousUser The anonymous user.
     */
    public function __construct(
        private readonly KeycloakUserRepository $userRepository,
        private readonly KeycloakConfiguration $config,
        private readonly WebConfiguration $web,
        private readonly KeycloakSessionManager $sessionManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser()
    ) {
    }

    /**
     * {@inheritDoc}
     *
     * It is the callback of Keycloak.
     */
    public function loginPath(): string
    {
        return $this->config->getCallbackPath();
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        $this->config->validateWeb();
    }

    /**
     * {@inheritDoc}
     *
     * It is the callback of Keycloak: the user comes back from Keycloak with a
     * code, that is exchanged for the tokens, and the session is renewed. It is
     * done here, and only here, because the code can be used once.
     *
     * @throws AuthenticationException If Keycloak answers with an error or the
     * callback is not the one of a login that this session started.
     */
    public function login(
        ServerRequestInterface $request,
        SessionInterface $session
    ): ?UserInterface {
        $queryParams = $request->getQueryParams();

        // Keycloak says why the user is not logged in (the user said no, for
        // example).
        $error = $queryParams['error_description'] ?? $queryParams['error'] ?? '';
        if (is_string($error) && $error !== '') {
            throw new AuthenticationException(['{message}', 'message' => $error], 400);
        }

        // The login must be one that this session started.
        $storedState = $this->sessionManager->getState($session);
        if (!$storedState) {
            throw new AuthenticationException('No state parameter found in the session.', 400);
        }

        $state = $queryParams['state'] ?? '';
        if (!is_string($state) || !hash_equals($storedState, $state)) {
            throw new AuthenticationException(
                'State parameter does not match the stored state in the session.',
                400
            );
        }

        $code = $queryParams['code'] ?? '';
        if (!is_string($code) || $code === '') {
            throw new AuthenticationException('No authorization code received.', 400);
        }

        try {
            // Exchange the code for the tokens (with the PKCE code of this
            // login), and verify the ID token: it is the one of this login (its
            // nonce) and it was given by the realm to this client.
            $tokenInfo = $this->userRepository->exchangeCodeForToken(
                $code,
                $this->sessionManager->getPkceCode($session)
            );

            if (empty($tokenInfo['id_token'])) {
                throw new AuthenticationException('The ID token was not received.', 400);
            }

            $idToken = $this->userRepository->verifyIdToken(
                $tokenInfo['id_token'],
                (string) $this->sessionManager->getNonce($session)
            );

            // Get the user (the access token is verified) and check that it is
            // the user of the ID token.
            $userInfo = $this->userRepository->getUserInfoFromToken($tokenInfo['access_token']);
            if (($idToken['sub'] ?? null) !== ($userInfo['sub'] ?? null)) {
                throw new AuthenticationException(
                    'The user of the ID token is not the user of the access token.',
                    400
                );
            }

            $this->sessionManager->storeAuthInfo($session, $tokenInfo);
            $this->sessionManager->storeUserInfo($session, $userInfo);
        } catch (AuthenticationException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new AuthenticationException(
                ['Authentication failed: {error}', 'error' => $e->getMessage()],
                400,
                $e
            );
        }

        // The state is used once.
        $this->sessionManager->clearState($session);

        // The identifier that the session had before the login must be of no use
        // after it (session fixation).
        $this->sessionManager->regenerate($session);

        Flash::success($request, 'Successfully logged in.');

        return $this->userRepository->createUser($userInfo);
    }

    /**
     * {@inheritDoc}
     *
     * The user of the session is a copy made when the user logged in, and it is
     * asked to Keycloak again when the token expires or, if it is before, every
     * `refresh_interval` seconds: the roles may have changed, or Keycloak may
     * have ended the session.
     *
     *   - Keycloak gives new tokens: the session and its user are renewed.
     *   - Keycloak says that the refresh token is not valid (the session ended,
     *     the user was disabled): the session is closed.
     *   - Keycloak can not be asked (it does not answer, it fails, it refuses for
     *     a reason that is not about the session): nothing is thrown away, and
     *     the user is not let in without being verified. The next request asks
     *     again, so the session goes on when Keycloak is back.
     */
    public function userFromSession(SessionInterface $session): ?UserInterface
    {
        if ($this->sessionManager->isRefreshDue($session, $this->web->getRefreshInterval())) {
            $refreshToken = $this->sessionManager->getRefreshToken($session);

            if ($refreshToken === null) {
                // Nothing to ask with: a token that expired is the end of the
                // session, one that did not goes on until it does.
                if ($this->sessionManager->isTokenExpired($session)) {
                    $this->sessionManager->clearSession($session);

                    return $this->anonymousUser;
                }
            } else {
                try {
                    $tokenInfo = $this->userRepository->refreshToken($refreshToken);

                    // The new tokens are kept at once: a refresh token that
                    // Keycloak renews can not be used twice, so the one that was
                    // given must not be lost if what follows fails.
                    $this->sessionManager->storeAuthInfo($session, $tokenInfo);

                    try {
                        $userInfo = $this->userRepository->getUserInfoFromToken($tokenInfo['access_token']);
                    } catch (ProviderUnavailableException) {
                        // The next request asks again, with the new tokens.
                        $this->sessionManager->forgetCheck($session);

                        return null;
                    }

                    $this->sessionManager->storeUserInfo($session, $userInfo);

                    return $this->userRepository->createUser($userInfo);
                } catch (ProviderUnavailableException) {
                    return null;
                } catch (AuthenticationException) {
                    $this->sessionManager->clearSession($session);

                    return $this->anonymousUser;
                }
            }
        }

        // The user that the session has.
        $userInfo = $this->sessionManager->getUserInfo($session);
        if ($userInfo) {
            return $this->userRepository->createUser($userInfo);
        }

        return null;
    }

    /**
     * {@inheritDoc}
     *
     * The user is sent to Keycloak to end its session there too (OpenID Connect
     * RP-Initiated Logout), which sends it back to the page that follows the
     * logout. Otherwise the user would still have a session in Keycloak, and the
     * next login would not ask for the password. Without an ID token in the
     * session, or if it is not wanted (`end_session`), the user goes straight to
     * that page.
     */
    public function logoutUrl(ServerRequestInterface $request, ?SessionInterface $session): ?string
    {
        $idToken = $session ? $this->sessionManager->getIdToken($session) : null;

        if (!$this->config->isEndSession() || $idToken === null) {
            return null;
        }

        return $this->userRepository->getLogoutUrl($idToken, $this->web->getLogoutRedirectPath());
    }

    /**
     * {@inheritDoc}
     *
     * The user is sent to Keycloak, and what the login needs when it comes back
     * is kept in the session: the state (CSRF), the nonce of the ID token and the
     * PKCE code.
     */
    public function loginRedirect(ServerRequestInterface $request, SessionInterface $session): ?ResponseInterface
    {
        // Generate authorization URL.
        $authUrl = $this->userRepository->createAuthorizationUrl();

        $this->sessionManager->storeState($session, $this->userRepository->getState());
        $this->sessionManager->storeLogin(
            $session,
            $this->userRepository->getNonce(),
            $this->userRepository->getPkceCode()
        );

        return new RedirectResponse($authUrl);
    }
}
