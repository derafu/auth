<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Controller;

use Derafu\Auth\Contract\AuthenticationProviderInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Minimal callback controller for OAuth2 flow.
 */
class CallbackController implements RequestHandlerInterface
{
    /**
     * Constructor of the callback controller.
     *
     * @param AuthenticationProviderInterface $authProvider
     * @param SessionManagerInterface $sessionManager
     */
    public function __construct(
        private readonly AuthenticationProviderInterface $authProvider,
        private readonly SessionManagerInterface $sessionManager
    ) {
    }

    /**
     * Handle the callback request.
     *
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();

        // Check for errors.
        if (isset($queryParams['error'])) {
            return new JsonResponse(['error' => $queryParams['error']], 400);
        }

        // Verify state parameter.
        $state = $queryParams['state'] ?? '';
        $storedState = $this->sessionManager->getState();

        if (!$storedState || $state !== $storedState) {
            return new JsonResponse(['error' => 'Invalid state parameter.'], 400);
        }

        // Get authorization code.
        $code = $queryParams['code'] ?? '';
        if (empty($code)) {
            return new JsonResponse(['error' => 'No authorization code received.'], 400);
        }

        try {
            // Exchange code for tokens.
            $tokens = $this->authProvider->exchangeCodeForToken($code);

            // Store authentication info.
            $this->sessionManager->storeAuthInfo(
                $tokens['access_token'],
                $tokens['refresh_token'] ?? null,
                $tokens['expires'] ?? null
            );

            // Get user info.
            $userInfo = $this->authProvider->getUserInfo($tokens['access_token']);
            $this->sessionManager->storeUserInfo($userInfo);

            // Clear state.
            $this->sessionManager->clearState();

            // Redirect to dashboard or stored URL.
            $redirectUrl = $this->sessionManager->getRedirectUrl() ?: '/dashboard';

            return new RedirectResponse($redirectUrl);

        } catch (AuthenticationException $e) {
            return new JsonResponse(['error' => 'Authentication failed.'], 400);
        }
    }
}
