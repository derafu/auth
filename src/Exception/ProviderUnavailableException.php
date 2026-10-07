<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Exception;

/**
 * Exception thrown when the provider could not say whether a session is still
 * good: it does not answer, it fails, or it refuses for a reason that has
 * nothing to do with the session (the application is not known to it).
 *
 * It is not a rejection: a rejection (`AuthenticationException`) is the provider
 * saying that the session is over, and the session is closed. This one says
 * nothing about it, so nothing is thrown away: the user is not let in without
 * being verified, but the session stays for when the provider answers.
 */
class ProviderUnavailableException extends AuthenticationException
{
}
