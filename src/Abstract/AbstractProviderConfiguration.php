<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Abstract;

use Derafu\Auth\Contract\ConfigurationInterface;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Support\Url;

/**
 * Abstract provider configuration.
 *
 * This class provides a base implementation for all provider configurations.
 */
abstract class AbstractProviderConfiguration implements ConfigurationInterface
{
    /**
     * The protected paths.
     *
     * @var array
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

    /**
     * The login path.
     *
     * Must match the login route in the routing configuration.
     *
     * @var string
     */
    private string $loginPath = '/auth/login';

    /**
     * The logout path.
     *
     * Must match the logout route in the routing configuration.
     *
     * @var string
     */
    private string $logoutPath = '/auth/logout';

    /**
     * The login redirect path.
     *
     * Where the user will be redirected after login.
     */
    private string $loginRedirectPath = '/';

    /**
     * The logout redirect path.
     *
     * Where the user will be redirected after logout.
     *
     * @var string
     */
    private string $logoutRedirectPath = '/';

    /**
     * The unauthorized redirect path.
     *
     * Where the user will be redirected if they are unauthorized.
     *
     * @var string
     */
    private string $unauthorizedRedirectPath = '/';

    /**
     * Whether the authentication is enabled.
     *
     * This is useful to disable the authentication for development purposes.
     *
     * @var bool
     */
    private bool $enabled = true;

    private ?int $refreshInterval = null;

    /**
     * The paths of the API, in their canonical form.
     *
     * @var list<string>
     */
    private array $apiPaths = ['/api'];

    /**
     * The realm that the response 401 of the API announces.
     */
    private string $apiRealm = 'API';

    /**
     * Creates a new abstract provider configuration.
     *
     * This must be called by the child class constructor.
     *
     * @param array<string, mixed> $config The configuration array.
     */
    public function __construct(array $config)
    {
        // Protected paths.
        $protectedPaths = $config['protected_paths']
            ?? $this->protectedPaths
        ;
        $this->protectedPaths = [];
        $this->rules = [];
        foreach ($protectedPaths as $key => $value) {
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

        // Login and logout paths.
        $this->loginPath = $config['login_path']
            ?? $this->loginPath
        ;
        $this->logoutPath = $config['logout_path']
            ?? $this->logoutPath
        ;

        // Redirect paths.
        $this->loginRedirectPath = $config['login_redirect_path']
            ?? $this->loginRedirectPath
        ;
        $this->logoutRedirectPath = $config['logout_redirect_path']
            ?? $this->logoutRedirectPath
        ;
        $this->unauthorizedRedirectPath = $config['unauthorized_redirect_path']
            ?? $this->unauthorizedRedirectPath
        ;

        // Enabled.
        $this->enabled = $config['enabled']
            ?? $this->enabled
        ;

        // Every how many seconds the user of a session is asked to the provider
        // again (its roles, that it still exists). 0 or not given: the provider
        // decides (see `getRefreshInterval()`).
        $refreshInterval = $config['refresh_interval'] ?? null;
        if ($refreshInterval !== null && (!is_int($refreshInterval) || $refreshInterval < 0)) {
            throw new ConfigurationException(
                'The refresh interval must be a number of seconds, 0 or more.'
            );
        }
        $this->refreshInterval = $refreshInterval === 0 ? null : $refreshInterval;

        // The API: its paths, and the label of its protection space.
        $apiPaths = $config['api_paths'] ?? $this->apiPaths;
        $this->apiPaths = [];
        foreach ((array) $apiPaths as $apiPath) {
            $canonical = is_string($apiPath) && trim($apiPath) !== '' ? Url::normalizePath($apiPath) : null;
            // The root would make the whole site the API.
            if ($canonical === null || $canonical === '/') {
                throw new ConfigurationException([
                    'The path of the API "{path}" is not valid.',
                    'path' => is_string($apiPath) ? $apiPath : get_debug_type($apiPath),
                ]);
            }
            $this->apiPaths[] = $canonical;
        }

        // It goes in a header between quotes: nothing that could end them.
        $apiRealm = $config['api_realm'] ?? $this->apiRealm;
        if (!is_string($apiRealm) || trim($apiRealm) === '' || preg_match('/[\x00-\x1f\x7f"\\\\]/', $apiRealm)) {
            throw new ConfigurationException('The realm of the API must be a text without quotes, backslashes or control characters.');
        }
        $this->apiRealm = trim($apiRealm);
    }

    /**
     * {@inheritDoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return match ($key) {
            'protected_paths' => $this->getProtectedPaths(),
            'login_path' => $this->getLoginPath(),
            'logout_path' => $this->getLogoutPath(),
            'login_redirect_path' => $this->getLoginRedirectPath(),
            'logout_redirect_path' => $this->getLogoutRedirectPath(),
            'unauthorized_redirect_path' => $this->getUnauthorizedRedirectPath(),
            'enabled' => $this->isEnabled(),
            'refresh_interval' => $this->getRefreshInterval(),
            'api_paths' => $this->getApiPaths(),
            'api_realm' => $this->getApiRealm(),
            default => $default,
        };
    }

    /**
     * {@inheritDoc}
     */
    public function toArray(): array
    {
        return [
            'protected_paths' => $this->getProtectedPaths(),
            'login_path' => $this->getLoginPath(),
            'logout_path' => $this->getLogoutPath(),
            'login_redirect_path' => $this->getLoginRedirectPath(),
            'logout_redirect_path' => $this->getLogoutRedirectPath(),
            'unauthorized_redirect_path' => $this->getUnauthorizedRedirectPath(),
            'enabled' => $this->isEnabled(),
            'refresh_interval' => $this->getRefreshInterval(),
            'api_paths' => $this->getApiPaths(),
            'api_realm' => $this->getApiRealm(),
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function getApiPaths(): array
    {
        return $this->apiPaths;
    }

    /**
     * {@inheritDoc}
     */
    public function getApiRealm(): string
    {
        return $this->apiRealm;
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
     */
    public function getLoginPath(): string
    {
        return $this->loginPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getLogoutPath(): string
    {
        return $this->logoutPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getLoginRedirectPath(): string
    {
        return $this->loginRedirectPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getLogoutRedirectPath(): string
    {
        return $this->logoutRedirectPath;
    }

    /**
     * {@inheritDoc}
     */
    public function getUnauthorizedRedirectPath(): string
    {
        return $this->unauthorizedRedirectPath;
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
    public function getRefreshInterval(): ?int
    {
        return $this->refreshInterval;
    }

    /**
     * {@inheritDoc}
     *
     * The roles are the ones of the most specific rule that the path is under
     * (see `requiresAuth()`): with the rules `/api` and `/api/human_resources`,
     * the path `/api/human_resources/x` needs the roles of the second one, no
     * matter the order in which they were written.
     */
    public function allowedRoles(string $path): array
    {
        // If the authentication is not enabled, no role is needed.
        if (!$this->isEnabled()) {
            return [];
        }

        // If no protected path matches, no role is needed.
        return $this->ruleOf($path)['roles'] ?? [];
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
     */
    public function requiresAuth(string $path): bool
    {
        // If the authentication is not enabled, return false.
        if (!$this->isEnabled()) {
            return false;
        }

        if (Url::normalizePath($path) === null) {
            return true;
        }

        return $this->ruleOf($path) !== null;
    }

    /**
     * Finds the most specific rule that a path is under.
     *
     * @param string $path The path.
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
