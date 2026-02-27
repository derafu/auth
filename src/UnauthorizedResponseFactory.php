<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth;

use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;

/**
 * Unauthorized response factory.
 */
class UnauthorizedResponseFactory
{
    public function __invoke(): PsrResponseInterface
    {
        return new JsonResponse(
            [
                'status' => 401,
                'title' => 'Unauthorized',
                'detail' => 'The user is not authorized to access this resource.',
            ],
            401
        );
    }
}
