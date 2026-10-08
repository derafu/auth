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
 * What a client of the API does to get its token: it asks the token endpoint of
 * the realm, as a service (`client_credentials`) or as a person that gives its
 * password (`password`), the way that a program does. The answer has the access
 * token, and the ID token and the refresh token if they were asked.
 */
final class KeycloakTokens
{
    private readonly Client $http;

    public function __construct(private readonly string $url, private readonly string $realm = 'test')
    {
        $this->http = new Client(['http_errors' => false]);
    }

    /**
     * The token of a service: its client and its secret.
     *
     * @return array<string, mixed>
     */
    public function service(string $clientId, string $secret): array
    {
        return $this->request([
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $secret,
        ]);
    }

    /**
     * The token of a person that gives its user and its password to a client.
     *
     * @return array<string, mixed>
     */
    public function person(string $clientId, string $username, string $password, string $scope = 'openid'): array
    {
        return $this->request([
            'grant_type' => 'password',
            'client_id' => $clientId,
            'username' => $username,
            'password' => $password,
            'scope' => $scope,
        ]);
    }

    /**
     * @param array<string, string> $form
     * @return array<string, mixed>
     */
    private function request(array $form): array
    {
        $response = $this->http->post(
            $this->url . '/realms/' . $this->realm . '/protocol/openid-connect/token',
            ['form_params' => $form]
        );
        $answer = json_decode((string) $response->getBody(), true);

        if ($response->getStatusCode() !== 200 || !is_array($answer) || !isset($answer['access_token'])) {
            throw new RuntimeException('Keycloak did not give a token: ' . $response->getBody());
        }

        return $answer;
    }
}
