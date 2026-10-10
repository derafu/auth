<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak\Api;

use DateTimeImmutable;
use Derafu\Auth\Authentication\Channel\Api\Scheme\BearerScheme;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Provider\Keycloak\KeycloakConfiguration;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Psr\Cache\CacheItemPoolInterface;

/**
 * The scheme of the API of Keycloak: the access token that Keycloak gave to a
 * client, `Bearer`. A service (with `client_credentials`) and a person send the
 * same thing.
 *
 * The token is verified by what it says (see
 * `KeycloakTokenVerifier::verifyBearerToken()`): nothing is asked to Keycloak
 * but its keys, that are cached, so a request does not wait for it, unless the
 * introspection is on (it is, by default): then Keycloak is asked whether the
 * token is still active. The user has the roles of the realm and the ones of the
 * client of the audience.
 *
 * It also reads an **offline token** (`typ: Offline`), the token of the API that a
 * user makes in its profile: a refresh token that does not depend on a session. It
 * is exchanged with Keycloak for an access token, with the credentials of the
 * client of the application (a token that another client made is refused by
 * Keycloak), and from there it is the same: the access token is verified, and
 * Keycloak says whether it is still active, so a token that the user revoked, or of
 * a user that was disabled, stops working at once. The roles are the ones that
 * Keycloak gives at the exchange. The access token that was exchanged is kept in the
 * cache pool, if the application has one, until it is about to expire, so a request
 * does not wait for the exchange.
 */
class KeycloakBearerScheme extends BearerScheme
{
    /**
     * Creates the scheme.
     *
     * @param KeycloakUserRepository $userRepository The user repository.
     * @param KeycloakConfiguration $config The configuration of Keycloak.
     */
    /**
     * The seconds before its expiry that an exchanged access token stops being
     * used: so it never expires in the middle of a request.
     */
    private const MARGIN = 30;

    /**
     * The reasons that a client is told as they are: they say what is wrong with
     * its token and nothing of what Keycloak answered.
     */
    private const REASONS = [
        'The token is not an access token.',
        'The audience of the token is not this API.',
        'The issuer of the token is not the realm.',
        'The token is not active.',
        'Keycloak did not accept the offline token.',
    ];

    /**
     * @param CacheItemPoolInterface|null $cache Where the access tokens that were
     * exchanged for an offline token are kept until they expire.
     */
    public function __construct(
        private readonly KeycloakUserRepository $userRepository,
        private readonly KeycloakConfiguration $config,
        private readonly ?CacheItemPoolInterface $cache = null
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function validate(): void
    {
        $this->config->validateApi();
    }

    /**
     * {@inheritDoc}
     */
    protected function authenticateToken(string $token): ?UserInterface
    {
        try {
            return TokenClaims::isOffline($token)
                ? $this->authenticateOfflineToken($token)
                : $this->userOfAccessToken($token)
            ;
        } catch (AuthenticationException $e) {
            // The client is told why, with one of a few texts: what the exception
            // says can have what Keycloak answered, and that is not for the client.
            throw new AuthenticationException(self::reasonOf($e), 401, $e);
        }
    }

    /**
     * The reason that the client is given for a token that is not valid.
     */
    private static function reasonOf(AuthenticationException $e): string
    {
        return match (true) {
            $e->getPrevious() instanceof ExpiredException => 'The token has expired.',
            $e->getPrevious() instanceof SignatureInvalidException => 'The signature of the token is not valid.',
            $e->getPrevious() instanceof BeforeValidException => 'The token is not valid yet.',
            in_array($e->getMessage(), self::REASONS, true) => $e->getMessage(),
            default => 'The token is not valid.',
        };
    }

    /**
     * The user of an access token: it is verified (and Keycloak says that it is
     * active, unless the introspection is off).
     *
     * @throws AuthenticationException If the token is not valid, or not active.
     */
    private function userOfAccessToken(string $accessToken): UserInterface
    {
        return $this->userRepository->createUser(
            $this->userRepository->verifyBearerToken($accessToken),
            $this->config->getApiAudience()
        );
    }

    /**
     * The user of an offline token: the access token that Keycloak gives for it.
     *
     * @throws AuthenticationException If Keycloak does not accept the token (it was
     * revoked, it is of another client, the user was disabled), or what it gives is
     * not valid.
     */
    private function authenticateOfflineToken(string $offlineToken): UserInterface
    {
        $key = 'derafu_auth.offline.' . hash('sha256', $offlineToken);

        // The access token of a previous request, if it is still good: if Keycloak
        // does not consider it active (the token was revoked) it is forgotten, and
        // Keycloak is asked again, which is the one that says that the token is not
        // valid.
        $cached = $this->cache?->getItem($key);
        if ($cached !== null && $cached->isHit()) {
            try {
                return $this->userOfAccessToken((string) $cached->get());
            } catch (AuthenticationException) {
                $this->cache->deleteItem($key);
            }
        }

        try {
            $tokens = $this->userRepository->refreshToken($offlineToken);
        } catch (AuthenticationException $e) {
            throw new AuthenticationException('Keycloak did not accept the offline token.', 401, $e);
        }
        $user = $this->userOfAccessToken($tokens['access_token']);

        if ($this->cache !== null && isset($tokens['expires'])) {
            $this->cache->save(
                $this->cache->getItem($key)
                    ->set($tokens['access_token'])
                    ->expiresAt(new DateTimeImmutable('@' . ((int) $tokens['expires'] - self::MARGIN)))
            );
        }

        return $user;
    }
}
