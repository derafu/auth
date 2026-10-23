<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Authentication\Channel\Web;

use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Translation\Contract\TranslatableMessageInterface;
use Derafu\Translation\TranslatableMessage;
use Mezzio\Flash\FlashMessageMiddleware;
use Mezzio\Flash\FlashMessagesInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The flash messages of the web channel: what the user is told in the next page.
 *
 * A flash message is the message as data (its id, its parameters and its domain),
 * not a text: it is translated when it is shown, in the language of whoever sees
 * it (see `partials/flash-messages.html.twig`). A session that keeps JSON, like
 * the one of Mezzio, can keep it. Without the flash middleware nothing is kept.
 */
final class Flash
{
    /**
     * Gets the flash messages of the request.
     *
     * @return FlashMessagesInterface|null The flash messages or null if not available.
     * @throws ConfigurationException If the request contains an invalid flash service.
     */
    public static function of(ServerRequestInterface $request): ?FlashMessagesInterface
    {
        $flash = $request->getAttribute(FlashMessageMiddleware::FLASH_ATTRIBUTE);
        if ($flash !== null && !$flash instanceof FlashMessagesInterface) {
            throw new ConfigurationException('The flash request attribute must implement Mezzio\\Flash\\FlashMessagesInterface.');
        }

        return $flash;
    }

    /**
     * Adds an error flash message.
     *
     * @param string|TranslatableMessageInterface $message The message: its text
     * in English, which is its translation id, or a message already made (the one
     * of an exception, for example).
     * @param array<string, mixed> $parameters The parameters of the text. A message
     * that is already made has its own.
     * @param bool $now Whether to add the flash message immediately.
     */
    public static function error(
        ServerRequestInterface $request,
        string|TranslatableMessageInterface $message,
        array $parameters = [],
        bool $now = false
    ): void {
        $flash = self::of($request);
        if ($flash === null) {
            return;
        }

        $message = self::message($message, $parameters);

        if ($now) {
            $flash->flashNow('error', $message, 0);
        } else {
            $flash->flash('error', $message);
        }
    }

    /**
     * Adds a success flash message.
     *
     * It is a message as data, like the one of `error()`.
     *
     * @param string|TranslatableMessageInterface $message The message: its text
     * in English, which is its translation id, or a message already made.
     * @param array<string, mixed> $parameters The parameters of the text.
     * @param bool $now Whether to add the flash message immediately.
     */
    public static function success(
        ServerRequestInterface $request,
        string|TranslatableMessageInterface $message,
        array $parameters = [],
        bool $now = false
    ): void {
        $flash = self::of($request);
        if ($flash === null) {
            return;
        }

        $message = self::message($message, $parameters);

        if ($now) {
            $flash->flashNow('success', $message, 0);
        } else {
            $flash->flash('success', $message);
        }
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private static function message(string|TranslatableMessageInterface $message, array $parameters): TranslatableMessageInterface
    {
        return $message instanceof TranslatableMessageInterface
            ? $message
            : new TranslatableMessage($message, $parameters, 'auth');
    }
}
