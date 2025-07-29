<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Middleware;

use Derafu\Auth\Contract\AuthenticationProviderInterface;
use Derafu\Auth\Contract\RouteValidatorInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Authentication middleware for PSR-15.
 *
 * This middleware handles the authentication flow by:
 *
 *   - Checking if the user is already authenticated.
 *   - Redirecting to the authentication provider if needed.
 *   - Processing authentication callbacks.
 *   - Adding user information to the request.
 */
class AuthenticationMiddleware implements MiddlewareInterface
{
    /**
     * Creates a new authentication middleware.
     *
     * @param AuthenticationProviderInterface $authProvider The authentication
     * provider.
     * @param SessionManagerInterface $sessionManager The session manager.
     * @param RouteValidatorInterface $routeValidator The route validator.
     */
    public function __construct(
        private readonly AuthenticationProviderInterface $authProvider,
        private readonly SessionManagerInterface $sessionManager,
        private readonly RouteValidatorInterface $routeValidator
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $path = $request->getUri()->getPath();

        // Handle logout.
        if ($this->routeValidator->isLogoutPath($path)) {
            $this->sessionManager->clear();
            return new RedirectResponse('/');
        }

        // Handle authentication callback.
        if ($this->routeValidator->isCallbackPath($path)) {
            return $this->handleCallback($request);
        }

        // Check if user is already authenticated.
        if ($this->sessionManager->hasAuthInfo()) {
            // Check if token has expired.
            if ($this->sessionManager->isTokenExpired()) {
                $refreshToken = $this->sessionManager->getRefreshToken();
                if ($refreshToken) {
                    try {
                        // Refresh token.
                        $tokenInfo = $this->authProvider->refreshToken(
                            $refreshToken
                        );

                        // Store new token information.
                        $this->sessionManager->storeAuthInfo(
                            $tokenInfo['access_token'],
                            $tokenInfo['refresh_token'] ?? null,
                            $tokenInfo['expires'] ?? null
                        );
                    } catch (AuthenticationException $e) {
                        $this->sessionManager->clear();
                        return $this->redirectToAuth($request);
                    }
                } else {
                    $this->sessionManager->clear();
                    return $this->redirectToAuth($request);
                }
            }

            // Add user information to request.
            $userInfo = $this->sessionManager->getUserInfo();
            $request = $request->withAttribute('user', $userInfo);
            $request = $request->withAttribute(
                'access_token',
                $this->sessionManager->getAccessToken()
            );

            return $handler->handle($request);
        }

        // Check if route requires authentication.
        if ($this->routeValidator->requiresAuth($path)) {
            return $this->redirectToAuth($request);
        }

        // Route doesn't require authentication, continue.
        return $handler->handle($request);
    }

    /**
     * Handles the authentication callback.
     *
     * @param ServerRequestInterface $request The request.
     * @return ResponseInterface The response.
     */
    private function handleCallback(
        ServerRequestInterface $request
    ): ResponseInterface {
        $queryParams = $request->getQueryParams();
        $savedState = $this->sessionManager->getState();

        // Verify state parameter for CSRF protection.
        if (!isset($queryParams['state']) || $savedState !== $queryParams['state']) {
            $this->sessionManager->clearState();
            return new JsonResponse(['error' => 'Invalid state parameter'], 400);
        }

        // Process authorization code.
        if (!isset($queryParams['code'])) {
            return new JsonResponse(['error' => 'No authorization code provided'], 400);
        }

        try {
            // Exchange code for token.
            $tokenInfo = $this->authProvider->exchangeCodeForToken($queryParams['code']);

            // Store authentication information.
            $this->sessionManager->storeAuthInfo(
                $tokenInfo['access_token'],
                $tokenInfo['refresh_token'] ?? null,
                $tokenInfo['expires'] ?? null
            );

            // Get and store user information.
            $userInfo = $this->authProvider->getUserInfo($tokenInfo['access_token']);
            $this->sessionManager->storeUserInfo($userInfo);

            // Clear state.
            $this->sessionManager->clearState();

            // Redirect to original URL or home.
            $redirectUrl = $this->sessionManager->getRedirectUrl();
            return new RedirectResponse($redirectUrl);

        } catch (AuthenticationException $e) {
            return new JsonResponse([
                'error' => 'Authentication failed',
                'message' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Redirects to the authentication provider.
     *
     * @param ServerRequestInterface $request The request.
     * @return ResponseInterface The redirect response.
     */
    private function redirectToAuth(
        ServerRequestInterface $request
    ): ResponseInterface {
        // Store current URL for redirect after authentication.
        $this->sessionManager->storeRedirectUrl((string) $request->getUri());

        // Generate authorization URL.
        $authUrl = $this->authProvider->createAuthorizationUrl();

        // Store state for CSRF protection.
        $state = $this->authProvider->getState();
        $this->sessionManager->storeState($state);

        return new RedirectResponse($authUrl);
    }
}
