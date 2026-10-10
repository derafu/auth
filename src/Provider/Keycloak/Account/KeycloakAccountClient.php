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
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;

/**
 * The account API of Keycloak (`/realms/{realm}/account`), with the access token
 * of the user itself: what a user can see and do with its own sessions, with no
 * administrator and no credentials of the application.
 *
 * The tokens of the API are offline sessions. The list of the sessions of the user
 * has all of them (`sessions/devices`) and the one of the sessions that depend on
 * a login has only those (`sessions`), so the offline ones are the difference. The
 * identifier of a session is the claim `sid` of its token, and it is what revokes
 * it: one token, and no other. It needs the roles `view-profile` and
 * `manage-account` of the client `account`, which a realm gives to its users by
 * default.
 */
class KeycloakAccountClient
{
    /**
     * The client of the account API of every realm, and the roles that it asks.
     */
    private const ACCOUNT_CLIENT = 'account';

    private const ROLE_READ = 'view-profile';

    private const ROLE_REVOKE = 'manage-account';

    /**
     * What Keycloak says of a browser that it does not know (the requests of a
     * program have no browser): it is not shown as one.
     */
    private const UNKNOWN_BROWSER = 'Other/Unknown';

    private readonly ClientInterface $http;

    public function __construct(
        private readonly KeycloakConfiguration $config,
        ?ClientInterface $http = null
    ) {
        $this->http = $http ?? new Client($config->getHttpClientOptions());
    }

    /**
     * The tokens of the API of the user: its offline sessions of this client.
     *
     * @return list<ApiToken> The newest first.
     * @throws AuthenticationException If Keycloak does not let the user see them.
     * @throws ProviderUnavailableException If Keycloak does not answer.
     */
    public function tokens(string $accessToken): array
    {
        $online = [];
        foreach ($this->get($accessToken, '/sessions') as $session) {
            $online[(string) ($session['id'] ?? '')] = true;
        }

        $tokens = [];
        foreach ($this->get($accessToken, '/sessions/devices') as $device) {
            foreach ($device['sessions'] ?? [] as $session) {
                $id = (string) ($session['id'] ?? '');
                if ($id === '' || isset($online[$id]) || !$this->isOfThisClient($session)) {
                    continue;
                }

                $tokens[] = new ApiToken(
                    $id,
                    (int) ($session['started'] ?? 0),
                    (int) ($session['lastAccess'] ?? 0),
                    (int) ($session['expires'] ?? 0),
                    isset($session['ipAddress']) ? (string) $session['ipAddress'] : null,
                    isset($session['browser']) && $session['browser'] !== self::UNKNOWN_BROWSER ? (string) $session['browser'] : null
                );
            }
        }

        usort($tokens, fn (ApiToken $a, ApiToken $b) => $b->createdAt <=> $a->createdAt);

        return $tokens;
    }

    /**
     * Whether the user has a second factor (a code of an app) set up: the account API
     * lists the kinds of credentials of the user, with the ones that it has.
     *
     * @throws AuthenticationException If Keycloak does not let the user see them.
     * @throws ProviderUnavailableException If Keycloak does not answer.
     */
    public function hasSecondFactor(string $accessToken): bool
    {
        foreach ($this->get($accessToken, '/credentials') as $credential) {
            if (($credential['type'] ?? null) === 'otp' && !empty($credential['userCredentialMetadatas'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * What Keycloak says about a session of login of the user.
     *
     * @return array<string, mixed>|null The session, or null if it is not there.
     * @throws AuthenticationException If Keycloak does not let the user see it.
     * @throws ProviderUnavailableException If Keycloak does not answer.
     */
    public function session(string $accessToken, string $id): ?array
    {
        foreach ($this->get($accessToken, '/sessions') as $session) {
            if (($session['id'] ?? null) === $id) {
                return $session;
            }
        }

        return null;
    }

    /**
     * Revokes a session of the user: the token stops working at once.
     *
     * @throws AuthenticationException If Keycloak does not let the user do it.
     * @throws ProviderUnavailableException If Keycloak does not answer.
     */
    public function revoke(string $accessToken, string $id): void
    {
        $this->requireRole($accessToken, self::ROLE_REVOKE);

        $status = $this->request('DELETE', $accessToken, '/sessions/' . rawurlencode($id))['status'];

        if ($status !== 204 && $status !== 200) {
            throw new AuthenticationException(
                ['Keycloak did not revoke the token (HTTP status {status}).', 'status' => $status],
                400
            );
        }
    }

    /**
     * Whether a session has this client (the application): the sessions of the
     * other applications of the user are not its tokens.
     *
     * @param array<string, mixed> $session
     */
    private function isOfThisClient(array $session): bool
    {
        foreach ($session['clients'] ?? [] as $client) {
            if (($client['clientId'] ?? null) === $this->config->getClientId()) {
                return true;
            }
        }

        return false;
    }

    /**
     * That the token of the session has the role that the account API asks, which
     * the token says itself: if it does not, Keycloak answers with a `401` that does
     * not say what is missing, and this does (the usual cause is a client that does
     * not have *Full scope allowed* and has not the role in its scope).
     *
     * @throws AuthenticationException If the token does not have the role.
     */
    private function requireRole(string $accessToken, string $role): void
    {
        $roles = TokenClaims::of($accessToken)['resource_access'][self::ACCOUNT_CLIENT]['roles'] ?? [];
        if (is_array($roles) && in_array($role, $roles, true)) {
            return;
        }

        if ($role === self::ROLE_REVOKE) {
            throw new AuthenticationException(
                [
                    'The token of your session does not have the role {role} of the client {client}, that Keycloak asks to revoke a token. Add it to the scope of the client {application}.',
                    'role' => $role,
                    'client' => self::ACCOUNT_CLIENT,
                    'application' => $this->config->getClientId(),
                ],
                403
            );
        }

        throw new AuthenticationException(
            [
                'The token of your session does not have the role {role} of the client {client}, that Keycloak asks to read the sessions. Add it to the scope of the client {application}.',
                'role' => $role,
                'client' => self::ACCOUNT_CLIENT,
                'application' => $this->config->getClientId(),
            ],
            403
        );
    }

    /**
     * A list of the account API.
     *
     * @return list<array<string, mixed>>
     */
    private function get(string $accessToken, string $path): array
    {
        $this->requireRole($accessToken, self::ROLE_READ);

        $answer = $this->request('GET', $accessToken, $path);

        if ($answer['status'] !== 200 || !is_array($answer['body'])) {
            throw new AuthenticationException(
                ['Keycloak did not let the sessions be read (HTTP status {status}).', 'status' => $answer['status']],
                $answer['status'] === 401 || $answer['status'] === 403 ? 403 : 400
            );
        }

        return array_values($answer['body']);
    }

    /**
     * @return array{status: int, body: mixed}
     */
    private function request(string $method, string $accessToken, string $path): array
    {
        try {
            $response = $this->http->request($method, $this->config->getRealmUrl() . '/account' . $path, [
                'headers' => ['Authorization' => 'Bearer ' . $accessToken, 'Accept' => 'application/json'],
                'http_errors' => false,
            ]);
        } catch (Exception $e) {
            throw new ProviderUnavailableException(
                ['Failed to read the account of Keycloak: {error}', 'error' => $e->getMessage()],
                0,
                $e
            );
        }

        return [
            'status' => $response->getStatusCode(),
            'body' => json_decode((string) $response->getBody(), true),
        ];
    }
}
