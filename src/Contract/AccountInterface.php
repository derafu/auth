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

use Derafu\Translation\Contract\TranslatableMessageInterface;
use Mezzio\Session\SessionInterface;

/**
 * What a provider gives to the pages of the account of a user (the profile): what
 * it knows about the user and about the session, where the user edits its data,
 * how a client authenticates in the API with it, and the tokens of the API if it
 * has them.
 *
 * The page is the same for every provider (`AccountController`); what changes is
 * what each one says here.
 */
interface AccountInterface
{
    /**
     * The address of the page of the provider where the user edits its data (the
     * account console of Keycloak), or null if there is none: the profile of the
     * site is read-only.
     */
    public function accountUrl(): ?string;

    /**
     * What the provider says about the user, besides what every user has
     * (identity, name, email, roles).
     *
     * @return list<array{label: TranslatableMessageInterface|string, value: mixed}>
     * The fields, in order. The label is a message to translate (or its text in
     * English, which is its translation id).
     */
    public function profile(UserInterface $user, SessionInterface $session): array;

    /**
     * What the provider says about the session of the user (what is not about the
     * session of PHP, which every provider has).
     *
     * @return list<array{title: TranslatableMessageInterface|string, fields: list<array{label: TranslatableMessageInterface|string, value: mixed}>}>
     * The sections, each with its title and its fields.
     */
    public function sessionDetails(SessionInterface $session): array;

    /**
     * The scheme of the header `Authorization` that a client of the API uses with
     * this provider: `Basic` or `Bearer`.
     */
    public function apiScheme(): string;

    /**
     * The tokens of the API that the user can have, or null if the provider has
     * none (a client uses its user and password).
     */
    public function tokens(): ?ApiTokenManagerInterface;
}
