<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Contract;

/**
 * A way of authenticating the users: what the package asks of each provider.
 *
 * The application uses one, chosen with `AUTH_PROVIDER` (see
 * `AuthProviderRegistry`). The pieces of the package that depend on the provider
 * (the flow of the web channel, the scheme of the API, the account, the session
 * and the forms) are the ones that its implementation gives.
 *
 * To add a provider: implement this interface (extending `AuthProvider` is the
 * short way), define its services and tag the service of the provider with
 * `derafu_auth.provider`. Nothing of the package changes.
 */
interface AuthProviderInterface
{
    /**
     * The name of the provider: what `AUTH_PROVIDER` says to choose it. It is
     * static because the registry reads it without making the provider.
     */
    public static function name(): string;

    /**
     * What the provider gives to the web channel: how the user logs in.
     */
    public function webFlow(): WebFlowInterface;

    /**
     * The session of the web channel, with what the provider keeps in it.
     */
    public function sessionManager(): SessionManagerInterface;

    /**
     * The forms of the web channel, with the configuration of the provider.
     */
    public function forms(): FormManagerInterface;

    /**
     * What the provider gives to the API channel: how a client says who it is.
     */
    public function apiScheme(): ApiSchemeInterface;

    /**
     * The pages of the account of the user: its profile and, if the provider has
     * them, its tokens of the API.
     */
    public function account(): AccountInterface;

    /**
     * The paths that the provider needs the web channel to have when the
     * application does not say them (`AUTH_WEB_*`): a provider with a login page of
     * the site sends the user to it.
     *
     * @return array<string, string> Keys of `WebConfiguration`.
     */
    public function webDefaults(): array;
}
