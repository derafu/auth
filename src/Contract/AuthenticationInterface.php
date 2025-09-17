<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

use Mezzio\Authentication\AuthenticationInterface as MezzioAuthenticationInterface;
use Mezzio\Authentication\UserInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authentication interface that extends Mezzio's AuthenticationInterface.
 *
 * Provides a clear contract for authentication adapters while maintaining full
 * compatibility with Mezzio's authentication system.
 *
 * @method UserInterface|null authenticate(ServerRequestInterface $request)
 * @method ResponseInterface unauthorizedResponse(ServerRequestInterface $request)
 */
interface AuthenticationInterface extends MezzioAuthenticationInterface
{
}
