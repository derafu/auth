<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Account;

use Derafu\Translation\TranslatableMessage;
use Mezzio\Session\SessionIdentifierAwareInterface;
use Mezzio\Session\SessionInterface;

/**
 * What can be said about the session of PHP, the same for every provider: its
 * name, a piece of its identifier (never the whole, it is what opens the
 * session), how long it lasts and the parameters of its cookie.
 */
final class PhpSessionDetails
{
    /**
     * @return list<array{label: TranslatableMessage, value: mixed}>
     */
    public static function of(SessionInterface $session): array
    {
        $cookie = session_get_cookie_params();

        $details = [['label' => new TranslatableMessage('Session name', [], 'auth'), 'value' => session_name() ?: null]];

        if ($session instanceof SessionIdentifierAwareInterface && $session->getId() !== '') {
            $details[] = ['label' => new TranslatableMessage('Session identifier (start)', [], 'auth'), 'value' => substr($session->getId(), 0, 8) . '…'];
        }

        return [
            ...$details,
            ['label' => new TranslatableMessage('Session lifetime (seconds)', [], 'auth'), 'value' => ini_get('session.gc_maxlifetime') ?: null],
            ['label' => new TranslatableMessage('Cookie lifetime (seconds)', [], 'auth'), 'value' => $cookie['lifetime']],
            ['label' => new TranslatableMessage('Cookie path', [], 'auth'), 'value' => $cookie['path']],
            ['label' => new TranslatableMessage('Cookie domain', [], 'auth'), 'value' => self::textOrNull($cookie['domain'])],
            ['label' => new TranslatableMessage('Cookie secure', [], 'auth'), 'value' => $cookie['secure']],
            ['label' => new TranslatableMessage('Cookie HTTP only', [], 'auth'), 'value' => $cookie['httponly']],
            ['label' => new TranslatableMessage('Cookie same site', [], 'auth'), 'value' => self::textOrNull($cookie['samesite'])],
        ];
    }

    /**
     * A text, or null if it is empty.
     */
    private static function textOrNull(string $text): ?string
    {
        return $text === '' ? null : $text;
    }
}
