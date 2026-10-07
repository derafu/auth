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
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * The browser of a user of Keycloak: it keeps the cookies that Keycloak sets, so
 * its session (the single sign-on) goes from one request to the next, and it
 * does not follow the redirects, so what the test is about is seen.
 *
 * The cookies of Keycloak are `Secure`, as Keycloak is behind HTTPS in real life
 * and a browser accepts them from `localhost`: here they are sent on HTTP.
 */
final class KeycloakBrowser
{
    /**
     * @var array<string, string>
     */
    private array $cookies = [];

    private readonly Client $http;

    public function __construct()
    {
        $this->http = new Client(['allow_redirects' => false, 'http_errors' => false]);
    }

    /**
     * Visits a URL.
     */
    public function visit(string $url): ResponseInterface
    {
        return $this->send('GET', $url);
    }

    /**
     * The user opens the authorization URL and logs in on the page of Keycloak.
     *
     * @return array<string, string> The query of the redirect to the callback of
     * the application (the `code`, the `state`...).
     */
    public function logIn(string $authorizationUrl, string $username = 'ana', string $password = 'secret'): array
    {
        $page = $this->visit($authorizationUrl);
        if ($page->getStatusCode() !== 200) {
            throw new RuntimeException('Keycloak did not show the login page: ' . $page->getStatusCode());
        }

        $html = (string) $page->getBody();
        if (!preg_match('/<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/s', $html, $matches)) {
            throw new RuntimeException('The login form was not found in the page of Keycloak.');
        }

        $response = $this->send('POST', html_entity_decode($matches[1]), [
            'form_params' => ['username' => $username, 'password' => $password, 'credentialId' => ''],
        ]);

        return $this->callback($response);
    }

    /**
     * The query of the redirect that a response is.
     *
     * @return array<string, string>
     */
    public function callback(ResponseInterface $response): array
    {
        if ($response->getStatusCode() !== 302) {
            throw new RuntimeException('Keycloak did not redirect: ' . $response->getStatusCode());
        }

        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);

        return $query;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function send(string $method, string $url, array $options = []): ResponseInterface
    {
        $options['headers']['Cookie'] = implode('; ', array_map(
            fn (string $name, string $value) => $name . '=' . $value,
            array_keys($this->cookies),
            $this->cookies
        ));

        $response = $this->http->request($method, $url, $options);

        foreach ($response->getHeader('Set-Cookie') as $cookie) {
            [$pair] = explode(';', $cookie, 2);
            [$name, $value] = explode('=', $pair, 2);
            $this->cookies[$name] = $value;
        }

        return $response;
    }
}
