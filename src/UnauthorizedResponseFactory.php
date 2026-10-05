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

use Derafu\Translation\TranslatableMessage;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Unauthorized response factory.
 */
class UnauthorizedResponseFactory
{
    /**
     * Creates the factory.
     *
     * @param TranslatorInterface|null $translator Translates the title and the
     * detail of the response, in the language of the translator. Without it
     * they are in English.
     */
    public function __construct(
        private readonly ?TranslatorInterface $translator = null
    ) {
    }

    public function __invoke(): PsrResponseInterface
    {
        return new JsonResponse(
            [
                'status' => 401,
                'title' => $this->translate(new TranslatableMessage('Unauthorized', [], 'auth')),
                'detail' => $this->translate(new TranslatableMessage('The user is not authorized to access this resource.', [], 'auth')),
            ],
            401
        );
    }

    private function translate(TranslatableMessage $message): string
    {
        return $this->translator !== null
            ? $message->trans($this->translator)
            : (string) $message;
    }
}
