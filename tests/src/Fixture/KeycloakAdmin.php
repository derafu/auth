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

    /**
     * Creates a user that has a username and a password and nothing else: no
     * names, no email, no attributes.
     */
    public function createUser(string $username, string $password): void
    {
        // Keycloak asks a user that has no names or email to complete its profile
        // before it lets it in. A realm whose users do not need them says that the
        // action is not required.
        $this->setProfileVerification(false);

        $this->request('POST', '/users', [
            'username' => $username,
            'enabled' => true,
            'credentials' => [['type' => 'password', 'value' => $password, 'temporary' => false]],
        ]);
    }

    /**
     * Whether Keycloak asks a user to complete its profile (names and email)
     * before it logs in.
     */
    public function setProfileVerification(bool $enabled): void
    {
        $this->request('PUT', '/authentication/required-actions/VERIFY_PROFILE', [
            'alias' => 'VERIFY_PROFILE',
            'name' => 'Verify Profile',
            'providerId' => 'VERIFY_PROFILE',
            'enabled' => $enabled,
            'defaultAction' => false,
            'priority' => 90,
        ]);
    }

    public function deleteUser(string $username): void
    {
        $users = $this->request('GET', '/users?username=' . rawurlencode($username) . '&exact=true');
        if ($users !== []) {
            $this->request('DELETE', '/users/' . $users[0]['id']);
        }
    }

    public function addRealmRole(string $username, string $role): void
    {
        $this->request('POST', '/users/' . $this->userId($username) . '/role-mappings/realm', [$this->role($role)]);
    }

    public function removeRealmRole(string $username, string $role): void
    {
        $this->request('DELETE', '/users/' . $this->userId($username) . '/role-mappings/realm', [$this->role($role)]);
    }

    /**
     * Gives a role of a client to the user (the roles of the client `account` that
     * a realm gives by default to its users, which the test realm does not).
     */
    public function addClientRole(string $username, string $client, string $role): void
    {
        $uuid = $this->clientId($client);
        $found = $this->request('GET', '/clients/' . $uuid . '/roles/' . rawurlencode($role));

        $this->request(
            'POST',
            '/users/' . $this->userId($username) . '/role-mappings/clients/' . $uuid,
            [['id' => $found['id'], 'name' => $found['name']]]
        );
    }

    /**
     * How many offline sessions (tokens of the API) the user has for a client.
     */
    public function offlineSessions(string $username, string $client): int
    {
        return count($this->request(
            'GET',
            '/users/' . $this->userId($username) . '/offline-sessions/' . $this->clientId($client)
        ));
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
     * Leaves the realm and the users `ana` and `otto` as the file of the realm has them.
     */
    public function reset(): void
    {
        $this->updateRealm([
            'accessTokenLifespan' => 300,
            'revokeRefreshToken' => false,
            'refreshTokenMaxReuse' => 0,
        ]);
        $this->deleteUser('ben');
        $this->setProfileVerification(true);
        $this->setEnabled('ana', true);

        // The roles of the client `account` that a test gave, and the offline
        // sessions that it made.
        $account = $this->clientId('account');
        $given = array_column($this->request('GET', '/users/' . $this->userId('ana') . '/role-mappings/clients/' . $account), 'name');
        foreach (array_diff($given, ['view-profile']) as $role) {
            $found = $this->request('GET', '/clients/' . $account . '/roles/' . rawurlencode($role));
            $this->request(
                'DELETE',
                '/users/' . $this->userId('ana') . '/role-mappings/clients/' . $account,
                [['id' => $found['id'], 'name' => $found['name']]]
            );
        }
        $this->deleteConsent('ana', 'derafu-auth');

        $roles = array_column($this->request('GET', '/users/' . $this->userId('ana') . '/role-mappings/realm'), 'name');
        foreach (array_diff($roles, ['admin', 'default-roles-test', 'offline_access', 'uma_authorization']) as $role) {
            $this->removeRealmRole('ana', $role);
        }
        if (!in_array('admin', $roles, true)) {
            $this->addRealmRole('ana', 'admin');
        }
        $this->logOut('ana');

        $this->setEnabled('otto', true);
        $this->deleteConsent('otto', 'derafu-auth');
        foreach (array_column($this->request('GET', '/users/' . $this->userId('otto') . '/role-mappings/realm'), 'name') as $role) {
            if (!in_array($role, ['admin', 'default-roles-test', 'offline_access', 'uma_authorization'], true)) {
                $this->removeRealmRole('otto', $role);
            }
        }
        $this->logOut('otto');
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

    /**
     * Removes what the user granted to a client, which ends its offline sessions.
     */
    private function deleteConsent(string $username, string $client): void
    {
        $response = $this->http->request(
            'DELETE',
            $this->url . '/admin/realms/' . self::REALM . '/users/' . $this->userId($username) . '/consents/' . rawurlencode($client),
            ['headers' => ['Authorization' => 'Bearer ' . $this->token()]]
        );
        if ($response->getStatusCode() >= 300 && $response->getStatusCode() !== 404) {
            throw new RuntimeException('The consent could not be removed: ' . $response->getStatusCode());
        }
    }

    private function clientId(string $client): string
    {
        $clients = $this->request('GET', '/clients?clientId=' . rawurlencode($client));

        return $clients[0]['id'] ?? throw new RuntimeException('The client "' . $client . '" is not in the realm.');
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
