<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization Library.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Flash\FlashMessagesInterface;
use Psr\Http\Message\ServerRequestInterface;
use Twig\Extension\AbstractExtension;
use Twig\Extension\GlobalsInterface;

/**
 * The variable `app` of the templates, as `derafu/http` gives it to a site: the
 * flash messages of the request that is being handled (the only thing of it that
 * the templates of the login need).
 */
final class AppGlobal extends AbstractExtension implements GlobalsInterface
{
    public ?ServerRequestInterface $request = null;

    /**
     * {@inheritDoc}
     */
    public function getGlobals(): array
    {
        return ['app' => new class ($this) {
            public function __construct(private readonly AppGlobal $global)
            {
            }

            /**
             * @return array<string, mixed>
             */
            public function getFlashes(): array
            {
                $flash = $this->global->request?->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE);

                return $flash instanceof FlashMessagesInterface ? $flash->getFlashes() : [];
            }
        }];
    }
}
