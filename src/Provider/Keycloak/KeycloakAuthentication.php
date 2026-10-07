<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak;

use Derafu\Auth\Abstract\AbstractProviderAuthentication;
use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Exception;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Keycloak authentication implementation for Mezzio.
 *
 * This class implements our AuthenticationInterface to provide
 * OAuth2/OpenID Connect authentication with Keycloak.
 */
class KeycloakAuthentication extends AbstractProviderAuthentication implements AuthenticationInterface
{
    /**
     * Creates a new Keycloak authentication implementation.
     *
     * @param KeycloakUserRepository $userRepository The user repository.
     * @param KeycloakConfiguration $config The configuration.
     * @param KeycloakSessionManager $sessionManager The session manager.
     * @param UserInterface $anonymousUser The anonymous user.
     * @param TranslatorInterface|null $translator Translates the response of an
     * unauthenticated request to the API.
     */
    public function __construct(
        private readonly KeycloakUserRepository $userRepository,
        private readonly KeycloakConfiguration $config,
        private readonly KeycloakSessionManager $sessionManager,
        private readonly UserInterface $anonymousUser = new AnonymousUser(),
        ?TranslatorInterface $translator = null
    ) {
        parent::__construct(
            config: $config,
            sessionManager: $sessionManager,
            anonymousUser: $anonymousUser,
            translator: $translator
        );
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
    protected function handleLogin(
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

        $this->addSuccessFlash($request, 'Successfully logged in.');

        return new KeycloakUser($userInfo, $this->config->getClientId());
    }

    /**
     * {@inheritDoc}
     */
    protected function getAuthenticatedUserFromSession(SessionInterface $session): ?UserInterface
    {
        // Check if token has expired.
        if ($this->sessionManager->isTokenExpired($session)) {
            $refreshToken = $this->sessionManager->getRefreshToken($session);
            if ($refreshToken) {
                try {
                    $tokenInfo = $this->userRepository->refreshToken($refreshToken);
                    $this->sessionManager->storeAuthInfo($session, $tokenInfo);

                    // Get updated user info.
                    $userInfo = $this->userRepository->getUserInfoFromToken(
                        $tokenInfo['access_token']
                    );
                    $this->sessionManager->storeUserInfo($session, $userInfo);

                    return new KeycloakUser($userInfo, $this->config->getClientId());
                } catch (AuthenticationException) {
                    $this->sessionManager->clearSession($session);
                    return $this->anonymousUser;
                }
            } else {
                $this->sessionManager->clearSession($session);
                return $this->anonymousUser;
            }
        }

        // Return existing user.
        $userInfo = $this->sessionManager->getUserInfo($session);
        if ($userInfo) {
            return new KeycloakUser($userInfo, $this->config->getClientId());
        }

        // If the user info is not found, return null.
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * The session of the application is closed, and the user is sent to Keycloak
     * to end its session there too (OpenID Connect RP-Initiated Logout), which
     * sends the user back to the page that follows the logout. Otherwise the user
     * would still have a session in Keycloak, and the next login would not ask
     * for the password. Without an ID token in the session, or if it is not
     * wanted (`end_session`), the user goes straight to that page.
     */
    protected function handleLogout(ServerRequestInterface $request): PsrResponseInterface
    {
        $session = $this->getSessionFromRequest($request);
        $idToken = $session ? $this->sessionManager->getIdToken($session) : null;

        $response = parent::handleLogout($request);

        if (!$this->config->isEndSession() || $idToken === null) {
            return $response;
        }

        return new RedirectResponse($this->userRepository->getLogoutUrl($idToken));
    }

    /**
     * {@inheritDoc}
     */
    protected function handleUnauthorized(
        ServerRequestInterface $request,
        SessionInterface $session
    ): PsrResponseInterface {
        $this->rememberPage($request, $session);

        // Generate authorization URL.
        $authUrl = $this->userRepository->createAuthorizationUrl();

        // Store what the login needs when the user comes back: the state (CSRF),
        // the nonce of the ID token and the PKCE code.
        $this->sessionManager->storeState($session, $this->userRepository->getState());
        $this->sessionManager->storeLogin(
            $session,
            $this->userRepository->getNonce(),
            $this->userRepository->getPkceCode()
        );

        return new RedirectResponse($authUrl);
    }
}
