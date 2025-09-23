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

use Derafu\Auth\Exception\AuthenticationException;
use Exception;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Minimal callback controller for Keycloak flow.
 */
class KeycloakController implements RequestHandlerInterface
{
    /**
     * Constructor of the Keycloak controller.
     *
     * @param KeycloakUserRepository $userRepository The user repository.
     * @param KeycloakSessionManager $sessionManager The session manager.
     */
    public function __construct(
        private readonly KeycloakConfiguration $config,
        private readonly KeycloakUserRepository $userRepository,
        private readonly KeycloakSessionManager $sessionManager,
    ) {
    }

    /**
     * Handle the Keycloak callback request.
     *
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();

        // Check for errors.
        if (!empty($queryParams['error_description'])) {
            throw new AuthenticationException($queryParams['error_description'], 400);
        }

        // Verify session.
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        if (!$session instanceof SessionInterface) {
            throw new AuthenticationException('Session not available.', 500);
        }

        // Verify state parameter in session.
        $storedState = $this->sessionManager->getState($session);
        if (!$storedState) {
            throw new AuthenticationException(
                'No state parameter found in the session.',
                400
            );
        }

        // Verify state parameter in query params.
        $state = $queryParams['state'] ?? '';
        if ($state !== $storedState) {
            throw new AuthenticationException(
                'State parameter does not match the stored state in the session.',
                400
            );
        }

        // Get authorization code.
        $code = $queryParams['code'] ?? '';
        if (empty($code)) {
            throw new AuthenticationException('No authorization code received.', 400);
        }

        try {
            // Exchange code for tokens.
            $tokens = $this->userRepository->exchangeCodeForToken($code);

            // Store authentication info.
            $this->sessionManager->storeAuthInfo($session, $tokens);

            // Get user info.
            $userInfo = $this->userRepository->getUserInfoFromToken($tokens['access_token']);
            $this->sessionManager->storeUserInfo($session, $userInfo);

            // Clear state.
            $this->sessionManager->clearState($session);

            // Redirect to dashboard or stored URL.
            $redirectUrl = $this->sessionManager->getRedirectUrl($session)
                ?: $this->config->getLoginRedirectRoute()
            ;

            return new RedirectResponse($redirectUrl);

        } catch (Exception $e) {
            if ($e instanceof AuthenticationException) {
                throw $e;
            }

            throw new AuthenticationException(
                sprintf('Authentication failed: %s', $e->getMessage()),
                400,
                $e
            );
        }
    }
}
