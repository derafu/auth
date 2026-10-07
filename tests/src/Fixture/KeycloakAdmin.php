<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use GuzzleHttp\Client;
use RuntimeException;

/**
 * The administrator of the Keycloak of the tests, through its REST API: what a
 * person that manages the realm does while a user has a session (takes a role
 * away, disables the user, ends its sessions) and what a realm is configured
 * with (how long a token lasts, whether a refresh token can be used twice).
 *
 * The realm and the user of the tests are changed by the tests, so `reset()`
 * leaves them as the file of the realm has them.
 */
final class KeycloakAdmin
{
    private const REALM = 'test';

    private readonly Client $http;

    public function __construct(private readonly string $url)
    {
        $this->http = new Client(['http_errors' => false]);
    }

    /**
     * How long an access token lasts, in seconds.
     */
    public function setAccessTokenLifespan(int $seconds): void
    {
        $this->updateRealm(['accessTokenLifespan' => $seconds]);
    }

    /**
     * Whether a refresh token can be used only once (the provider gives a new
     * one with each refresh, and the one that was used is revoked).
     */
    public function setRevokeRefreshToken(bool $revoke): void
    {
        $this->updateRealm(['revokeRefreshToken' => $revoke, 'refreshTokenMaxReuse' => 0]);
    }

    public function addRealmRole(string $username, string $role): void
    {
        $this->request('POST', '/users/' . $this->userId($username) . '/role-mappings/realm', [$this->role($role)]);
    }

    public function removeRealmRole(string $username, string $role): void
    {
        $this->request('DELETE', '/users/' . $this->userId($username) . '/role-mappings/realm', [$this->role($role)]);
    }

    public function setEnabled(string $username, bool $enabled): void
    {
        $this->request('PUT', '/users/' . $this->userId($username), ['enabled' => $enabled]);
    }

    /**
     * Ends all the sessions of the user in Keycloak.
     */
    public function logOut(string $username): void
    {
        $this->request('POST', '/users/' . $this->userId($username) . '/logout');
    }

    /**
     * Leaves the realm and the user `ana` as the file of the realm has them.
     */
    public function reset(): void
    {
        $this->updateRealm([
            'accessTokenLifespan' => 300,
            'revokeRefreshToken' => false,
            'refreshTokenMaxReuse' => 0,
        ]);
        $this->setEnabled('ana', true);

        $roles = array_column($this->request('GET', '/users/' . $this->userId('ana') . '/role-mappings/realm'), 'name');
        foreach (array_diff($roles, ['admin', 'default-roles-test', 'offline_access', 'uma_authorization']) as $role) {
            $this->removeRealmRole('ana', $role);
        }
        if (!in_array('admin', $roles, true)) {
            $this->addRealmRole('ana', 'admin');
        }
        $this->logOut('ana');
    }

    /**
     * Changes only what is given (what is not stays as it is). The whole
     * representation of the realm is not sent back: the empty objects that it has
     * come back as empty lists, and Keycloak does not take them.
     *
     * @param array<string, mixed> $changes
     */
    private function updateRealm(array $changes): void
    {
        $this->request('PUT', '', $changes);
    }

    private function userId(string $username): string
    {
        $users = $this->request('GET', '/users?username=' . rawurlencode($username) . '&exact=true');

        return $users[0]['id'] ?? throw new RuntimeException('The user "' . $username . '" is not in the realm.');
    }

    /**
     * @return array<string, mixed>
     */
    private function role(string $name): array
    {
        // What a role mapping needs, and nothing else (the rest has empty
        // objects that do not survive being sent back).
        $role = $this->request('GET', '/roles/' . rawurlencode($name));

        return ['id' => $role['id'], 'name' => $role['name']];
    }

    /**
     * @param array<mixed>|null $body
     * @return array<mixed>
     */
    private function request(string $method, string $path, ?array $body = null): array
    {
        $options = ['headers' => ['Authorization' => 'Bearer ' . $this->token()]];
        if ($body !== null) {
            $options['json'] = $body;
        }

        $response = $this->http->request($method, $this->url . '/admin/realms/' . self::REALM . $path, $options);
        if ($response->getStatusCode() >= 300) {
            throw new RuntimeException(sprintf(
                'The administration of Keycloak answered %d to %s %s: %s',
                $response->getStatusCode(),
                $method,
                $path,
                (string) $response->getBody()
            ));
        }

        $decoded = json_decode((string) $response->getBody(), true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * A token of the administrator (they last a minute in the master realm, so
     * one is asked for each call).
     */
    private function token(): string
    {
        $response = $this->http->post($this->url . '/realms/master/protocol/openid-connect/token', [
            'form_params' => [
                'grant_type' => 'password',
                'client_id' => 'admin-cli',
                'username' => 'admin',
                'password' => 'admin',
            ],
        ]);
        $token = json_decode((string) $response->getBody(), true)['access_token'] ?? null;

        return is_string($token) ? $token : throw new RuntimeException('Keycloak did not give a token to the administrator.');
    }
}
