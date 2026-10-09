<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication\Channel\Api\Scheme;

use Derafu\Auth\Authentication\LoginThrottle;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Contract\UserRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The scheme `Basic` (RFC 7617): the user and the password, separated by a colon,
 * in Base64 and in UTF-8, checked against the repository of users of a provider
 * that has a password for each user.
 *
 * The failed attempts are limited as the ones of the login form are, by identity
 * and by network of the client (see `LoginThrottle::clientOf()`): a program
 * guesses passwords much faster than a person. A client that is limited is not
 * asked anything, whatever it sent, so a password that is guessed while it is
 * limited is of no use. The user that does not exist, the one that has a wrong
 * password and the one that is not active are the same answer.
 *
 * The password is verified in each request, as it is in the login (with the cost
 * of the hash of the password): it is the price of not keeping anything.
 *
 * It does not know which provider it is for: the scheme of each provider extends
 * it and checks the configuration that its provider needs (`validate()`).
 */
abstract class BasicScheme implements ApiSchemeInterface
{
    /**
     * Creates the scheme.
     *
     * @param UserRepositoryInterface $repository Where the users are.
     * @param LoginThrottle|null $throttle Limits the failed attempts. Without it
     * they are not limited.
     */
    public function __construct(
        private readonly UserRepositoryInterface $repository,
        private readonly ?LoginThrottle $throttle = null
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function scheme(): string
    {
        return 'Basic';
    }

    /**
     * {@inheritDoc}
     *
     * @return UserInterface|null The user, or null if the credentials are not
     * valid or the client is limited.
     */
    public function authenticate(ServerRequestInterface $request, string $credentials): ?UserInterface
    {
        $basic = $this->credentials($credentials);
        if ($basic === null) {
            return null;
        }

        [$identity, $password] = $basic;
        $address = LoginThrottle::clientOf($request);

        if (($this->throttle?->retryAfter($identity, $address) ?? 0) > 0) {
            return null;
        }

        $user = $this->repository->authenticate($identity, $password);
        if (!$user instanceof UserInterface) {
            $this->throttle?->hit($identity, $address);

            return null;
        }

        $this->throttle?->clear($identity, $address);

        return $user;
    }

    /**
     * {@inheritDoc}
     *
     * The challenge of `Basic` is left out when the request says that it comes
     * from a script of a page (`X-Requested-With: XMLHttpRequest`): a browser
     * answers it with its own window to ask for a user and a password, and a page
     * that calls the API with its session wants the 401, not that window (Rails
     * and Spring do the same).
     */
    public function challenge(ServerRequestInterface $request, string $realm, bool $credentialsSent): ?string
    {
        if (strcasecmp($request->getHeaderLine('X-Requested-With'), 'XMLHttpRequest') === 0) {
            return null;
        }

        return sprintf('%s realm="%s", charset="UTF-8"', $this->scheme(), $realm);
    }

    /**
     * Reads the credentials: the user and the password.
     *
     * @param string $credentials What comes after `Basic`.
     * @return array{string, string}|null The identity and the password, or null if
     * it is not Base64, it is not UTF-8, it has no colon or its identity is empty.
     */
    private function credentials(string $credentials): ?array
    {
        $decoded = base64_decode($credentials, true);
        if ($decoded === false || !mb_check_encoding($decoded, 'UTF-8')) {
            return null;
        }

        $parts = explode(':', $decoded, 2);
        if (count($parts) !== 2 || $parts[0] === '') {
            return null;
        }

        return [$parts[0], $parts[1]];
    }
}
