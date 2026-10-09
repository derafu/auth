<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authorization;

use Derafu\Auth\Contract\AccessRulesInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Routing\Contract\RouteMatchInterface;
use Derafu\Support\Url;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The rules of access of the site: its protected paths, with the roles that each
 * one asks, and whether they are enforced.
 *
 * It is the one authority on who may enter which path, so the authentication and
 * the authorization do not have each its own idea of it. The roles that a request
 * needs are:
 *
 *   - The ones of the protected path that matches, if it has roles (the site
 *     decides over the routes that it imports).
 *   - Otherwise, the ones that the matched route declares.
 *
 * A route can also say that it needs an authenticated user with no particular
 * role (the default `requires_user`), and it is protected even when the site did
 * not list its path.
 */
class AccessRules implements AccessRulesInterface
{
    /**
     * The attribute name used to store the matched route.
     */
    public const ROUTE_ATTRIBUTE = 'derafu.route';

    /**
     * The default of a route that says that it needs an authenticated user (any
     * user, no role), whether the site listed its path or not: the pages of the
     * account of the user (`/auth/profile`) are the ones that declare it.
     */
    public const REQUIRES_USER = 'requires_user';

    /**
     * The protected paths.
     *
     * @var array<int|string, mixed>
     */
    private array $protectedPaths = [];

    /**
     * The rules of the protected paths, with their path in its canonical form
     * (see `Derafu\Support\Url::normalizePath()`), the roles and the number of
     * segments of the path: the rule that has more is the more specific.
     *
     * @var list<array{path: string, roles: array<string>, depth: int}>
     */
    private array $rules = [];

    private bool $enabled = true;

    /**
     * Creates the rules.
     *
     * @param array<string, mixed> $config The configuration:
     * `protected_paths` (a list of paths, or a map from a path to its roles) and
     * `enabled` (true by default: with false no path asks for a user, which is
     * useful in development and in tests).
     * @throws ConfigurationException If a path is not valid.
     */
    public function __construct(array $config = [])
    {
        foreach ((array) ($config['protected_paths'] ?? []) as $key => $value) {
            if (is_int($key)) {
                $path = $value;
                $roles = [];
            } else {
                $path = $key;
                $roles = is_array($value) ? $value : [$value];
            }

            // A rule that is not a path is not ignored: it would protect nothing
            // without anybody noticing.
            $canonical = is_string($path) && trim($path) !== '' ? Url::normalizePath($path) : null;
            if ($canonical === null) {
                throw new ConfigurationException([
                    'The protected path "{path}" is not valid.',
                    'path' => is_string($path) ? $path : get_debug_type($path),
                ]);
            }

            $this->protectedPaths[$path] = $roles;
            $this->rules[] = [
                'path' => $canonical,
                'roles' => $roles,
                'depth' => count((array) Url::pathSegments($canonical)),
            ];
        }

        $this->enabled = (bool) ($config['enabled'] ?? $this->enabled);
    }

    /**
     * Gets the roles that the matched route declares.
     *
     * @param ServerRequestInterface $request The request.
     * @return array<string> The roles, empty if there is no route or it
     * declares none.
     */
    public static function routeRoles(ServerRequestInterface $request): array
    {
        $route = $request->getAttribute(self::ROUTE_ATTRIBUTE);

        return $route instanceof RouteMatchInterface ? $route->getRoles() : [];
    }

    /**
     * Tells whether the matched route says that it needs an authenticated user
     * (see `REQUIRES_USER`).
     *
     * @param ServerRequestInterface $request The request.
     */
    public static function routeNeedsUser(ServerRequestInterface $request): bool
    {
        $route = $request->getAttribute(self::ROUTE_ATTRIBUTE);

        return $route instanceof RouteMatchInterface
            && ($route->getDefaults()[self::REQUIRES_USER] ?? false) === true
        ;
    }

    /**
     * {@inheritDoc}
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * {@inheritDoc}
     */
    public function getProtectedPaths(): array
    {
        return $this->protectedPaths;
    }

    /**
     * {@inheritDoc}
     *
     * A path is protected if it is under any of the rules, **by segments**: the
     * rule `/api` protects `/api`, `/api/index` and `/api/index/x`, and not
     * `/apiary`. The path and the rules are compared in their canonical form
     * (`/api//index`, `/api/./index` and `/api/%69ndex` are `/api/index`), and
     * without telling the case apart: a server that reads files from a file
     * system that does not (the one of macOS or Windows) serves `/Academy/x` with
     * the file of `/academy/x`, and the rule must not depend on that.
     *
     * A path that has no safe canonical form (it climbs a directory, it has an
     * escaped separator, a control character...) is protected: it can not be told
     * which rule it is under, so it is not let in without a user.
     *
     * A route that declares roles, or that says that it needs a user, is
     * protected, even when the site did not list its path.
     */
    public function requiresAuthentication(ServerRequestInterface $request): bool
    {
        return $this->isProtected($request->getUri()->getPath())
            || self::routeRoles($request) !== []
            || self::routeNeedsUser($request)
        ;
    }

    /**
     * {@inheritDoc}
     *
     * The roles are the ones of the most specific rule that the path is under: with
     * the rules `/api` and `/api/human_resources`, the path
     * `/api/human_resources/x` needs the roles of the second one, no matter the
     * order in which they were written.
     */
    public function requiredRoles(ServerRequestInterface $request): array
    {
        return $this->rolesOf($request->getUri()->getPath()) ?: self::routeRoles($request);
    }

    /**
     * Whether a path is under a protected path.
     */
    public function isProtected(string $path): bool
    {
        // If the rules are not enforced, nothing is protected.
        if (!$this->enabled) {
            return false;
        }

        if (Url::normalizePath($path) === null) {
            return true;
        }

        return $this->ruleOf($path) !== null;
    }

    /**
     * The roles that a path asks, by the most specific rule that it is under.
     *
     * @return array<string> The roles, empty if the rules are not enforced, no
     * rule matches, or the rule has none.
     */
    public function rolesOf(string $path): array
    {
        if (!$this->enabled) {
            return [];
        }

        return $this->ruleOf($path)['roles'] ?? [];
    }

    /**
     * Finds the most specific rule that a path is under.
     *
     * @return array{path: string, roles: array<string>, depth: int}|null The rule
     * that has the most segments (the first one written, if two have the same
     * path), or null if the path is not under any.
     */
    private function ruleOf(string $path): ?array
    {
        $found = null;
        foreach ($this->rules as $rule) {
            if (!Url::pathStartsWith($path, $rule['path'], caseSensitive: false)) {
                continue;
            }

            if ($found === null || $rule['depth'] > $found['depth']) {
                $found = $rule;
            }
        }

        return $found;
    }
}
