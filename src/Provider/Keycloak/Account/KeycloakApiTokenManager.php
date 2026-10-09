<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak\Account;

use Derafu\Auth\Account\ApiToken;
use Derafu\Auth\Contract\ApiTokenManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Translation\TranslatableMessage;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The tokens of the API of Keycloak: as many as the user wants, each one an offline
 * session that it can revoke by itself.
 */
class KeycloakApiTokenManager implements ApiTokenManagerInterface
{
    public function __construct(
        private readonly KeycloakUserRepository $userRepository,
        private readonly KeycloakAccountClient $account,
        private readonly KeycloakSessionManager $sessionManager
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function list(SessionInterface $session): array
    {
        return $this->account->tokens($this->accessToken($session));
    }

    /**
     * {@inheritDoc}
     */
    public function fields(): array
    {
        return [
            ['name' => 'password', 'label' => new TranslatableMessage('Password', [], 'auth'), 'type' => 'password', 'required' => true],
            ['name' => 'totp', 'label' => new TranslatableMessage('Code of the second factor (if you use one)', [], 'auth'), 'type' => 'text', 'required' => false],
        ];
    }

    /**
     * {@inheritDoc}
     *
     * The user gives its password again, and Keycloak makes the token as a session of
     * its own. The token must be of the user of the session: what the password opens
     * is checked, not taken for granted.
     */
    public function create(ServerRequestInterface $request, SessionInterface $session): string
    {
        $user = $request->getAttribute(MezzioUserInterface::class);
        if (!$user instanceof UserInterface || $user->isAnonymous()) {
            throw new AuthenticationException('There is no user in the session.', 401);
        }

        $body = $request->getParsedBody();
        $body = is_array($body) ? $body : [];
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';
        $otp = is_string($body['totp'] ?? null) ? trim($body['totp']) : null;
        if ($password === '') {
            throw new AuthenticationException('The password is not valid.', 401);
        }

        $answer = $this->userRepository->requestOfflineToken(
            $user->getUsername() ?? $user->getIdentity(),
            $password,
            $otp
        );

        $token = (string) $answer['refresh_token'];
        if ((TokenClaims::of($token)['sub'] ?? null) !== $user->getIdentity()) {
            throw new AuthenticationException('The token is not for the user of this session.', 400);
        }

        return $token;
    }

    /**
     * {@inheritDoc}
     *
     * Only a session that is a token of the user can be revoked: not its session of
     * login, nor one that is not its own.
     */
    public function revoke(SessionInterface $session, string $id): void
    {
        $accessToken = $this->accessToken($session);

        $mine = array_filter(
            $this->account->tokens($accessToken),
            fn (ApiToken $token) => $token->id === $id
        );
        if ($mine === []) {
            throw new AuthenticationException('The user has no such token.', 404);
        }

        $this->account->revoke($accessToken, $id);
    }

    /**
     * @throws AuthenticationException If the session has no access token.
     */
    private function accessToken(SessionInterface $session): string
    {
        return $this->sessionManager->getAccessToken($session)
            ?? throw new AuthenticationException('There is no session with Keycloak.', 401);
    }
}
