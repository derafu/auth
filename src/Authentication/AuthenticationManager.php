<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Contract\AccessRulesInterface;
use Derafu\Auth\Contract\AuthenticationInterface;
use Derafu\Auth\Contract\ChannelInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The manager of the authentication: the one entry point of the authentication
 * for Mezzio. It identifies who is asking, through the channels, and says "not
 * authenticated" to a request that needs a user and has none.
 *
 * It does not know how a request is identified (that is of each channel) nor
 * where the users are (that is of the providers): it asks the channels, in the
 * order they were given, the ones that match the request, until one knows who
 * is asking. What a path asks (a user, some roles) is not decided here either: it
 * is asked to the access rules. The only point where the authentication touches
 * authorization is the one that Mezzio imposes, that a request that needs a user
 * and has none is answered with `null`.
 *
 * A channel is added by tagging its service `derafu_auth.channel`.
 */
final class AuthenticationManager implements AuthenticationInterface
{
    /**
     * @var list<ChannelInterface>
     */
    private readonly array $channels;

    /**
     * Creates the manager.
     *
     * @param iterable<ChannelInterface> $channels The channels, in the order that
     * they are asked: the last one is the one that every request that is not of
     * another one ends in.
     * @param AccessRulesInterface $rules The rules of access.
     * @param UserInterface $anonymousUser The user of a request that no channel
     * identified.
     */
    public function __construct(
        iterable $channels,
        private readonly AccessRulesInterface $rules,
        private readonly UserInterface $anonymousUser = new AnonymousUser()
    ) {
        $this->channels = [...$channels];
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request): ?UserInterface
    {
        $matching = $this->matching($request);

        // The first channel that knows who is asking says it. One that has nothing
        // to say passes it to the next that matches: the API reads the credentials
        // of the header, and if there are none the session of the web may know.
        $user = null;
        foreach ($matching as $channel) {
            $identification = $channel->identify($request);

            if ($identification->isHalted()) {
                return null;
            }

            if ($identification->user() !== null) {
                $user = $identification->user();
                break;
            }
        }
        $user ??= $this->anonymousUser;

        // The way in and the way out are public: the access rules do not apply.
        if ($matching[0]->isPublic($request)) {
            return $user;
        }

        // A path that does not need a user lets anybody in.
        if (!$this->rules->requiresAuthentication($request)) {
            return $user;
        }

        // The path needs a user. `null` triggers the unauthorized response.
        return $user->isAnonymous() ? null : $user;
    }

    /**
     * {@inheritDoc}
     *
     * It is the response of the channel of the request (the first that matches): a
     * redirect to the login in the web, a 401 in the API.
     */
    public function unauthorizedResponse(ServerRequestInterface $request): ResponseInterface
    {
        return $this->matching($request)[0]->unauthorizedResponse($request);
    }

    /**
     * Gets the channels that match a request, in order.
     *
     * @return non-empty-list<ChannelInterface>
     * @throws ConfigurationException If no channel matches (the last one should
     * be the one of every request).
     */
    private function matching(ServerRequestInterface $request): array
    {
        $matching = [];
        foreach ($this->channels as $channel) {
            if ($channel->matches($request)) {
                $matching[] = $channel;
            }
        }

        if ($matching === []) {
            throw new ConfigurationException('No channel of authentication matches the request.');
        }

        return $matching;
    }
}
