<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Twig;

use Derafu\Auth\Account\AccountController;
use Derafu\Auth\Authentication\Channel\Web\WebConfiguration;
use Derafu\Auth\Contract\UserInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * What the templates use to know about the authentication, with the names of
 * Symfony:
 *
 *   - `is_granted('role')` (or a list of roles: any of them): whether the user of
 *     `app.user` has the role. Nobody is granted nothing.
 *   - `login_path()`, `logout_path()` and `profile_path()`: the paths of the
 *     login, the logout (a POST) and the profile.
 *
 * The user is read from the variable `app` of the template (see `AppVariable` in
 * `derafu/http`: `app.user`), so this package does not depend on the one of the
 * requests.
 */
final class AuthExtension extends AbstractExtension
{
    public function __construct(private readonly WebConfiguration $web)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function getFunctions(): array
    {
        return [
            new TwigFunction('is_granted', $this->isGranted(...), ['needs_context' => true]),
            new TwigFunction('login_path', fn (): string => $this->web->getLoginPath()),
            new TwigFunction('logout_path', fn (): string => $this->web->getLogoutPath()),
            new TwigFunction('profile_path', fn (): string => AccountController::PROFILE_PATH),
        ];
    }

    /**
     * Whether the user of the template has the role, or any of the roles.
     *
     * @param array<string, mixed> $context The variables of the template.
     * @param string|list<string> $roles
     */
    public function isGranted(array $context, string|array $roles): bool
    {
        $app = $context['app'] ?? null;
        $user = match (true) {
            is_object($app) && method_exists($app, 'getUser') => $app->getUser(),
            is_array($app) => $app['user'] ?? null,
            default => null,
        };

        if (!$user instanceof UserInterface || $user->isAnonymous()) {
            return false;
        }

        return $user->hasAnyRole((array) $roles);
    }
}
