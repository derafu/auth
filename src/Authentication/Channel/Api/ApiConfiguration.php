<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication\Channel\Api;

use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Support\Url;

/**
 * The configuration of the API channel: which paths are the API, and the label of
 * its protection space.
 */
class ApiConfiguration
{
    /**
     * The paths of the API, in their canonical form.
     *
     * @var list<string>
     */
    private array $paths = ['/api'];

    /**
     * The realm that the response 401 of the API announces.
     */
    private string $realm = 'API';

    /**
     * Creates the configuration.
     *
     * @param array<string, mixed> $config `paths` (a list of paths, `/api` by
     * default) and `realm` (a label, `API` by default).
     * @throws ConfigurationException If a path or the realm is not valid.
     */
    public function __construct(array $config = [])
    {
        $paths = [];
        foreach ((array) ($config['paths'] ?? $this->paths) as $path) {
            $canonical = is_string($path) && trim($path) !== '' ? Url::normalizePath($path) : null;
            // The root would make the whole site the API.
            if ($canonical === null || $canonical === '/') {
                throw new ConfigurationException([
                    'The path of the API "{path}" is not valid.',
                    'path' => is_string($path) ? $path : get_debug_type($path),
                ]);
            }
            $paths[] = $canonical;
        }
        $this->paths = $paths;

        // It goes in a header between quotes: nothing that could end them.
        $realm = $config['realm'] ?? $this->realm;
        if (!is_string($realm) || trim($realm) === '' || preg_match('/[\x00-\x1f\x7f"\\\\]/', $realm)) {
            throw new ConfigurationException('The realm of the API must be a text without quotes, backslashes or control characters.');
        }
        $this->realm = trim($realm);
    }

    /**
     * The paths of the API, in their canonical form.
     *
     * @return list<string>
     */
    public function getPaths(): array
    {
        return $this->paths;
    }

    /**
     * Whether a path is one of the API or is below one of them.
     */
    public function isApiPath(string $path): bool
    {
        foreach ($this->paths as $apiPath) {
            if (Url::pathStartsWith($path, $apiPath)) {
                return true;
            }
        }

        return false;
    }

    public function getRealm(): string
    {
        return $this->realm;
    }
}
