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

use Derafu\Auth\Contract\AccountInterface;
use Derafu\Auth\Contract\ApiTokenManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Translation\TranslatableMessage;
use Mezzio\Session\SessionInterface;

/**
 * The account of the provider of Keycloak: the user edits its data in the account
 * console of the realm, a client of the API sends a token with `Bearer`, and the
 * tokens are its offline sessions.
 *
 * What it says about the session is what the tokens of the session say (they are
 * the ones that Keycloak gave, already verified when the user logged in, so they
 * are read, not verified again) and, if Keycloak lets it be asked, what Keycloak
 * knows about the session.
 */
class KeycloakAccount implements AccountInterface
{
    public function __construct(
        private readonly KeycloakConfiguration $config,
        private readonly KeycloakSessionManager $sessionManager,
        private readonly KeycloakAccountClient $account,
        private readonly KeycloakApiTokenManager $tokens
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function accountUrl(): ?string
    {
        return $this->config->getAccountUrl();
    }

    /**
     * {@inheritDoc}
     */
    public function profile(UserInterface $user, SessionInterface $session): array
    {
        return [
            ['label' => new TranslatableMessage('Realm', [], 'auth'), 'value' => $this->config->getRealm()],
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function sessionDetails(SessionInterface $session): array
    {
        $sections = [];

        $access = TokenClaims::of((string) $this->sessionManager->getAccessToken($session));
        $refresh = TokenClaims::of((string) $this->sessionManager->getRefreshToken($session));

        if ($access !== []) {
            $sections[] = [
                'title' => new TranslatableMessage('Keycloak token', [], 'auth'),
                'fields' => array_values(array_filter([
                    ['label' => new TranslatableMessage('Issued at', [], 'auth'), 'value' => $this->time($access['iat'] ?? null)],
                    ['label' => new TranslatableMessage('Access token expires', [], 'auth'), 'value' => $this->time($access['exp'] ?? null)],
                    ['label' => new TranslatableMessage('Refresh token expires', [], 'auth'), 'value' => $this->time($refresh['exp'] ?? null)],
                    ['label' => new TranslatableMessage('Authenticated at', [], 'auth'), 'value' => $this->time($access['auth_time'] ?? null)],
                    ['label' => new TranslatableMessage('Session identifier', [], 'auth'), 'value' => $access['sid'] ?? null],
                    ['label' => new TranslatableMessage('Authentication level', [], 'auth'), 'value' => $access['acr'] ?? null],
                    ['label' => new TranslatableMessage('Client', [], 'auth'), 'value' => $access['azp'] ?? null],
                    ['label' => new TranslatableMessage('Scope', [], 'auth'), 'value' => $access['scope'] ?? null],
                ], fn (array $field) => $field['value'] !== null)),
            ];
        }

        $known = $this->known($session, $access['sid'] ?? null);
        if ($known !== null) {
            $sections[] = [
                'title' => new TranslatableMessage('Session in Keycloak', [], 'auth'),
                'fields' => array_values(array_filter([
                    ['label' => new TranslatableMessage('Started', [], 'auth'), 'value' => $this->time($known['started'] ?? null)],
                    ['label' => new TranslatableMessage('Last access', [], 'auth'), 'value' => $this->time($known['lastAccess'] ?? null)],
                    ['label' => new TranslatableMessage('Expires', [], 'auth'), 'value' => $this->time($known['expires'] ?? null)],
                    ['label' => new TranslatableMessage('IP address', [], 'auth'), 'value' => $known['ipAddress'] ?? null],
                    ['label' => new TranslatableMessage('Browser', [], 'auth'), 'value' => $known['browser'] ?? null],
                ], fn (array $field) => $field['value'] !== null)),
            ];
        }

        return $sections;
    }

    /**
     * {@inheritDoc}
     *
     * The site of the redirect URI of the client: it is the address that the site
     * has for Keycloak, so it is the one of the clients of its API.
     */
    public function publicUrl(): ?string
    {
        $uri = parse_url($this->config->getRedirectUri());
        if (!isset($uri['scheme'], $uri['host'])) {
            return null;
        }

        return $uri['scheme'] . '://' . $uri['host'] . (isset($uri['port']) ? ':' . $uri['port'] : '');
    }

    /**
     * {@inheritDoc}
     */
    public function apiScheme(): string
    {
        return 'Bearer';
    }

    /**
     * {@inheritDoc}
     */
    public function tokens(): ?ApiTokenManagerInterface
    {
        return $this->tokens;
    }

    /**
     * What Keycloak knows about the session, if it can be asked: the page is of use
     * without it.
     *
     * @return array<string, mixed>|null
     */
    private function known(SessionInterface $session, mixed $sid): ?array
    {
        $accessToken = $this->sessionManager->getAccessToken($session);
        if ($accessToken === null || !is_string($sid)) {
            return null;
        }

        try {
            return $this->account->session($accessToken, $sid);
        } catch (AuthenticationException|ProviderUnavailableException) {
            return null;
        }
    }

    /**
     * A moment of a token as a date, or null.
     */
    private function time(mixed $timestamp): ?string
    {
        return is_numeric($timestamp) ? date('Y-m-d H:i:s', (int) $timestamp) : null;
    }
}
