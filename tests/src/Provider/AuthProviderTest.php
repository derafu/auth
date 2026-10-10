<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider;

use Derafu\Auth\Contract\AccountInterface;
use Derafu\Auth\Contract\ApiSchemeInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\SessionManagerInterface;
use Derafu\Auth\Contract\WebFlowInterface;
use Derafu\Auth\Provider\AuthProvider;
use Derafu\Auth\Provider\Database\DatabaseAuthProvider;
use Derafu\Auth\Provider\Htpasswd\HtpasswdAuthProvider;
use Derafu\Auth\Provider\Keycloak\KeycloakAuthProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A provider gives the pieces that depend on it, when they are asked for, and
 * says its name, the one that `AUTH_PROVIDER` uses to choose it.
 */
#[CoversClass(AuthProvider::class)]
#[CoversClass(KeycloakAuthProvider::class)]
#[CoversClass(DatabaseAuthProvider::class)]
#[CoversClass(HtpasswdAuthProvider::class)]
final class AuthProviderTest extends TestCase
{
    /**
     * @param array<string, int> $made How many times each piece was made.
     * @return array<string, object>
     */
    private function pieces(array &$made = []): array
    {
        return [
            'webFlow' => $this->createStub(WebFlowInterface::class),
            'sessionManager' => $this->createStub(SessionManagerInterface::class),
            'forms' => $this->createStub(FormManagerInterface::class),
            'apiScheme' => $this->createStub(ApiSchemeInterface::class),
            'account' => $this->createStub(AccountInterface::class),
        ];
    }

    /**
     * @param class-string<AuthProvider> $class
     * @param array<string, object> $pieces
     * @param array<string, int> $made
     */
    private function provider(string $class, array $pieces, array &$made): AuthProvider
    {
        $closures = [];
        foreach ($pieces as $name => $piece) {
            $made[$name] = 0;
            $closures[$name] = function () use ($piece, $name, &$made): object {
                $made[$name]++;

                return $piece;
            };
        }

        return new $class(...$closures);
    }

    /**
     * @return array<string, array{class-string<AuthProvider>, string, array<string, string>}>
     */
    public static function providers(): array
    {
        return [
            'keycloak' => [KeycloakAuthProvider::class, 'keycloak', []],
            'database' => [DatabaseAuthProvider::class, 'database', ['logout_redirect_path' => '/auth/login', 'unauthorized_redirect_path' => '/auth/login']],
            'htpasswd' => [HtpasswdAuthProvider::class, 'htpasswd', ['logout_redirect_path' => '/auth/login', 'unauthorized_redirect_path' => '/auth/login']],
        ];
    }

    /**
     * @param class-string<AuthProvider> $class
     * @param array<string, string> $defaults
     */
    #[Test]
    #[DataProvider('providers')]
    public function aProviderSaysItsNameAndTheSitesPathsItNeeds(string $class, string $name, array $defaults): void
    {
        $made = [];
        $provider = $this->provider($class, $this->pieces(), $made);

        $this->assertSame($name, $class::name());
        $this->assertSame($defaults, $provider->webDefaults());
    }

    #[Test]
    public function aProviderGivesEachPieceItWasMadeWith(): void
    {
        $made = [];
        $pieces = $this->pieces();
        $provider = $this->provider(DatabaseAuthProvider::class, $pieces, $made);

        $this->assertSame($pieces['webFlow'], $provider->webFlow());
        $this->assertSame($pieces['sessionManager'], $provider->sessionManager());
        $this->assertSame($pieces['forms'], $provider->forms());
        $this->assertSame($pieces['apiScheme'], $provider->apiScheme());
        $this->assertSame($pieces['account'], $provider->account());
    }

    #[Test]
    public function aPieceIsMadeOnlyWhenItIsAskedFor(): void
    {
        $made = [];
        $provider = $this->provider(KeycloakAuthProvider::class, $this->pieces(), $made);

        // Nothing is made when the provider is: choosing it does not make what
        // it can give.
        $this->assertSame(['webFlow' => 0, 'sessionManager' => 0, 'forms' => 0, 'apiScheme' => 0, 'account' => 0], $made);

        $provider->apiScheme();

        $this->assertSame(['webFlow' => 0, 'sessionManager' => 0, 'forms' => 0, 'apiScheme' => 1, 'account' => 0], $made);
    }
}
