<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak;

use ArrayAccess;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ConfigurationException;
use Exception;
use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use UnexpectedValueException;

/**
 * Verifies the tokens that Keycloak gives: its signature (with the keys that the
 * realm publishes), its issuer, its expiration, and what the OpenID Connect
 * specification asks of an ID token (its audience and its nonce).
 *
 * The keys of the realm are cached when there is a cache pool (PSR-6): they are
 * read once an hour, and again when a token comes signed with a key that is not
 * known, because Keycloak rotated its keys (no more than ten times a minute).
 * Without a pool they are read once per verifier, and again if a token is signed
 * with a key that is not known.
 */
class KeycloakTokenVerifier
{
    /**
     * The seconds that the clocks of Keycloak and of the application can differ.
     */
    private const LEEWAY = 60;

    /**
     * The seconds that the keys of the realm are kept in the cache.
     */
    private const KEYS_TTL = 3600;

    /**
     * The keys of the realm, when there is no cache pool.
     *
     * @var array<string, Key>|null
     */
    private ?array $keys = null;

    private readonly ClientInterface $http;

    private readonly RequestFactoryInterface $requestFactory;

    /**
     * Constructor.
     *
     * @param KeycloakConfiguration $config The configuration.
     * @param CacheItemPoolInterface|null $cache Where the keys of the realm are
     * cached.
     * @param ClientInterface|null $http The client that reads the keys of the
     * realm. By default, one with the options of the configuration.
     * @param RequestFactoryInterface|null $requestFactory The factory of the
     * request for the keys. By default, the one of Guzzle.
     * @throws ConfigurationException If `firebase/php-jwt` is not installed, or
     * there is no client for the keys and `guzzlehttp/guzzle` (that comes with
     * `league/oauth2-client`) is not installed.
     */
    public function __construct(
        private readonly KeycloakConfiguration $config,
        private readonly ?CacheItemPoolInterface $cache = null,
        ?ClientInterface $http = null,
        ?RequestFactoryInterface $requestFactory = null
    ) {
        if (!class_exists(JWT::class)) {
            throw new ConfigurationException(
                'The Keycloak provider requires "firebase/php-jwt". Run: composer require firebase/php-jwt'
            );
        }

        if (($http === null || $requestFactory === null) && !class_exists(Client::class)) {
            throw new ConfigurationException(
                'The Keycloak provider requires "league/oauth2-client". Run: composer require league/oauth2-client'
            );
        }

        $this->http = $http ?? new Client($config->getHttpClientOptions());
        $this->requestFactory = $requestFactory ?? new HttpFactory();
    }

    /**
     * Verifies an ID token.
     *
     * @param string $idToken The ID token.
     * @param string $nonce The nonce that was sent in the authorization request.
     * @return array<string, mixed> The claims of the token.
     * @throws AuthenticationException If the token is not valid.
     */
    public function verifyIdToken(string $idToken, string $nonce): array
    {
        $claims = $this->decode($idToken);

        $audience = $claims['aud'] ?? [];
        if (!in_array($this->config->getClientId(), (array) $audience, true)) {
            throw new AuthenticationException('The audience of the token is not this client.');
        }

        if (!isset($claims['nonce']) || !hash_equals($nonce, (string) $claims['nonce'])) {
            throw new AuthenticationException('The nonce of the token is not the one of the login.');
        }

        return $claims;
    }

    /**
     * Verifies an access token.
     *
     * @param string $accessToken The access token.
     * @return array<string, mixed> The claims of the token.
     * @throws AuthenticationException If the token is not valid.
     */
    public function verifyAccessToken(string $accessToken): array
    {
        $claims = $this->decode($accessToken);

        // The token was given to this client.
        if (($claims['azp'] ?? null) !== $this->config->getClientId()) {
            throw new AuthenticationException('The token was not given to this client.');
        }

        return $claims;
    }

    /**
     * Verifies the access token that a client of the API sends.
     *
     * The token is the one of a service (`client_credentials`) or of a person,
     * that was given to any client of the realm: what makes it valid for this API
     * is its audience, so it must have the configured one (see
     * `KeycloakConfiguration::getApiAudience()`). Apart from the signature, the
     * issuer and the expiration, it must be an access token (an ID token, a
     * refresh token or an offline token are not one, they must not open the API).
     *
     * It is verified only by what it says: a token that was not revoked, of a
     * user that was disabled after it was given, is valid until it expires.
     *
     * @param string $accessToken The access token.
     * @param string $audience The audience that it must have.
     * @return array<string, mixed> The claims of the token.
     * @throws AuthenticationException If the token is not valid.
     */
    public function verifyBearerToken(string $accessToken, string $audience): array
    {
        $claims = $this->decode($accessToken);

        // Keycloak says "Bearer" in the access tokens; the ID token says "ID".
        if (($claims['typ'] ?? null) !== 'Bearer') {
            throw new AuthenticationException('The token is not an access token.');
        }

        if ($audience === '' || !in_array($audience, (array) ($claims['aud'] ?? []), true)) {
            throw new AuthenticationException('The audience of the token is not this API.');
        }

        return $claims;
    }

    /**
     * Decodes a token verifying its signature, its issuer and its expiration.
     *
     * @return array<string, mixed>
     */
    private function decode(string $jwt, bool $mayRetry = true): array
    {
        // What is not a token is not worth asking the realm for its keys.
        if (count(explode('.', $jwt)) !== 3) {
            throw new AuthenticationException(
                ['Failed to validate the token: {error}', 'error' => 'Wrong number of segments']
            );
        }

        $leeway = JWT::$leeway;

        try {
            JWT::$leeway = self::LEEWAY;

            $claims = (array) JWT::decode($jwt, $this->keys());
        } catch (Exception $e) {
            if (
                $mayRetry
                && $this->cache === null
                && $this->keys !== null
                && $e instanceof UnexpectedValueException
                && str_contains($e->getMessage(), '"kid"')
            ) {
                // Without a cache, the keys were read for this verifier and the
                // realm may have rotated them since: once more, fresh.
                $this->keys = null;

                return $this->decode($jwt, false);
            }

            throw new AuthenticationException(
                ['Failed to validate the token: {error}', 'error' => $e->getMessage()],
                0,
                $e
            );
        } finally {
            JWT::$leeway = $leeway;
        }

        if (($claims['iss'] ?? null) !== $this->config->getIssuer()) {
            throw new AuthenticationException('The issuer of the token is not the realm.');
        }

        return json_decode((string) json_encode($claims), true);
    }

    /**
     * The keys of the realm that sign: cached, or read once per verifier.
     *
     * @return array<string, Key>|ArrayAccess<string, Key>
     */
    private function keys(): array|ArrayAccess
    {
        $uri = $this->config->getRealmUrl() . '/protocol/openid-connect/certs';

        if ($this->cache !== null) {
            return new CachedKeySet(
                $uri,
                $this->http,
                $this->requestFactory,
                $this->cache,
                self::KEYS_TTL,
                true,
                'RS256'
            );
        }

        if ($this->keys === null) {
            $response = $this->http->sendRequest($this->requestFactory->createRequest('GET', $uri));
            $jwks = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);

            // The realm also publishes keys to encrypt: only the ones to sign.
            $jwks['keys'] = array_values(array_filter(
                $jwks['keys'] ?? [],
                fn (array $key) => ($key['use'] ?? 'sig') === 'sig'
            ));

            $this->keys = JWK::parseKeySet($jwks, 'RS256');
        }

        return $this->keys;
    }
}
