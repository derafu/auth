<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Authentication;

use Derafu\Auth\AnonymousUser;
use Derafu\Auth\Authentication\AuthenticationManager;
use Derafu\Auth\Authentication\Identification;
use Derafu\Auth\Contract\AccessRulesInterface;
use Derafu\Auth\Contract\ChannelInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\User;
use Derafu\TestsAuth\Fixture\FakeChannel;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The manager of the authentication knows nothing of how a request is identified
 * nor of what a path asks: it asks the channels that match, in order, until one
 * knows who is asking, and asks the access rules whether the path needs a user.
 * Here the channels are fakes that say what the test wants them to say.
 */
#[CoversClass(AuthenticationManager::class)]
#[UsesClass(Identification::class)]
#[UsesClass(AnonymousUser::class)]
#[UsesClass(User::class)]
#[UsesClass(ConfigurationException::class)]
final class AuthenticationManagerTest extends TestCase
{
    private function request(string $path = '/page'): ServerRequestInterface
    {
        return (new ServerRequest())->withUri(new Uri('https://app.test' . $path));
    }

    private function user(string $identity = 'ana'): UserInterface
    {
        return new User($identity, ['admin']);
    }

    private function channel(
        string $name,
        bool $matches,
        Identification $identification,
        bool $public = false
    ): FakeChannel {
        return new FakeChannel($name, $matches, $identification, $public);
    }

    private function rules(bool $requiresAuthentication): AccessRulesInterface
    {
        $rules = $this->createStub(AccessRulesInterface::class);
        $rules->method('requiresAuthentication')->willReturn($requiresAuthentication);

        return $rules;
    }

    /**
     * @param list<ChannelInterface> $channels
     */
    private function manager(array $channels, bool $requiresAuthentication = false): AuthenticationManager
    {
        return new AuthenticationManager($channels, $this->rules($requiresAuthentication));
    }

    #[Test]
    public function theFirstChannelThatKnowsWhoIsAskingSaysItAndTheNextOnesAreNotAsked(): void
    {
        $first = $this->channel('api', true, Identification::of($this->user('from-api')));
        $second = $this->channel('web', true, Identification::of($this->user('from-web')));

        $user = $this->manager([$first, $second])->authenticate($this->request());

        $this->assertSame('from-api', $user?->getIdentity());
        $this->assertSame(1, $first->asked);
        $this->assertSame(0, $second->asked);
    }

    #[Test]
    public function aChannelThatHasNothingToSayPassesItToTheNextOneThatMatches(): void
    {
        $api = $this->channel('api', true, Identification::none());
        $other = $this->channel('other', false, Identification::of($this->user('never')));
        $web = $this->channel('web', true, Identification::of($this->user('from-session')));

        $user = $this->manager([$api, $other, $web])->authenticate($this->request());

        $this->assertSame('from-session', $user?->getIdentity());
        $this->assertSame(1, $api->asked);
        // A channel that does not match the request is never asked.
        $this->assertSame(0, $other->asked);
    }

    #[Test]
    public function aRequestThatNoChannelIdentifiedIsTheAnonymousUser(): void
    {
        $user = $this->manager([$this->channel('web', true, Identification::none())])->authenticate($this->request());

        $this->assertTrue($user?->isAnonymous());
    }

    #[Test]
    public function aPathThatDoesNotNeedAUserLetsTheAnonymousUserIn(): void
    {
        $user = $this->manager([$this->channel('web', true, Identification::of(new AnonymousUser()))], false)
            ->authenticate($this->request());

        $this->assertTrue($user?->isAnonymous());
    }

    #[Test]
    public function aPathThatNeedsAUserAnswersNullToTheAnonymousOne(): void
    {
        $manager = $this->manager([$this->channel('web', true, Identification::of(new AnonymousUser()))], true);

        $this->assertNull($manager->authenticate($this->request()));
    }

    #[Test]
    public function aPathThatNeedsAUserLetsAUserIn(): void
    {
        $manager = $this->manager([$this->channel('web', true, Identification::of($this->user()))], true);

        $this->assertSame('ana', $manager->authenticate($this->request())?->getIdentity());
    }

    #[Test]
    public function aRequestThatEndsInTheChannelIsNullWhateverTheAccessRulesSay(): void
    {
        // A logout: it is answered by the channel.
        $channel = $this->channel('web', true, Identification::halt());

        $this->assertNull($this->manager([$channel], false)->authenticate($this->request()));
        $this->assertNull($this->manager([$channel], true)->authenticate($this->request()));
    }

    #[Test]
    public function theRequestThatTheChannelLetsThroughIsNotAskedToTheAccessRules(): void
    {
        // The way in and the way out are public, even when the path is protected.
        $channel = $this->channel('web', true, Identification::of(new AnonymousUser()), public: true);

        $this->assertTrue($this->manager([$channel], true)->authenticate($this->request())?->isAnonymous());
    }

    #[Test]
    public function theResponseOfAnUnauthorizedRequestIsTheOneOfTheFirstChannelThatMatches(): void
    {
        $manager = $this->manager([
            $this->channel('other', false, Identification::none()),
            $this->channel('api', true, Identification::none()),
            $this->channel('web', true, Identification::none()),
        ]);

        $this->assertSame('api', $manager->unauthorizedResponse($this->request())->getHeaderLine('X-Channel'));
    }

    #[Test]
    public function theChannelsCanBeGivenAsAnyIterable(): void
    {
        $manager = new AuthenticationManager(
            (fn () => yield $this->channel('web', true, Identification::of($this->user('generated'))))(),
            $this->rules(false)
        );

        $this->assertSame('generated', $manager->authenticate($this->request())?->getIdentity());
    }

    #[Test]
    public function aRequestThatNoChannelMatchesIsAnErrorOfTheConfiguration(): void
    {
        $manager = $this->manager([$this->channel('api', false, Identification::none())]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('No channel of authentication matches the request.');

        $manager->authenticate($this->request());
    }

    #[Test]
    public function theResponseOfARequestThatNoChannelMatchesIsAnErrorToo(): void
    {
        $this->expectException(ConfigurationException::class);

        $this->manager([])->unauthorizedResponse($this->request());
    }
}
