<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Whether a request comes from the same origin, by what the browser says.
 *
 * It is what makes a POST that changes something (the logout, the tokens of the
 * API) safe from a request that another site makes (cross-site request forgery):
 * the origin is what the browser says in `Sec-Fetch-Site` or in `Origin`. A
 * request that has neither is not made by a browser, and a browser always sends
 * one of them in a POST.
 */
final class SameOrigin
{
    /**
     * @return bool True if it does, or if it does not say (it is not a browser).
     */
    public static function of(ServerRequestInterface $request): bool
    {
        $site = $request->getHeaderLine('Sec-Fetch-Site');
        if ($site !== '') {
            return in_array($site, ['same-origin', 'none'], true);
        }

        $origin = $request->getHeaderLine('Origin');
        if ($origin === '') {
            return true;
        }

        $port = static fn (?string $scheme, ?int $port): ?int => $port
            ?? ['http' => 80, 'https' => 443][strtolower((string) $scheme)] ?? null;

        $from = parse_url($origin);
        $uri = $request->getUri();

        return strtolower((string) ($from['scheme'] ?? '')) === strtolower($uri->getScheme())
            && strtolower((string) ($from['host'] ?? '')) === strtolower($uri->getHost())
            && $port($from['scheme'] ?? null, $from['port'] ?? null) === $port($uri->getScheme(), $uri->getPort());
    }
}
