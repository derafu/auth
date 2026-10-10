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

use Derafu\Auth\Account\Form\ApiTokenValueForm;
use Derafu\Auth\Authentication\Channel\Web\Flash;
use Derafu\Auth\Authentication\SameOrigin;
use Derafu\Auth\Contract\AccountInterface;
use Derafu\Auth\Contract\ApiTokenManagerInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\AuthorizationException;
use Derafu\Auth\Exception\FormException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Renderer\Contract\RendererInterface;
use Derafu\Translation\TranslatableMessage;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The pages of the account of the user, the same for every provider: the profile
 * (its data, how to authenticate in the API and its tokens, and the data of the
 * session) and the creation and the revocation of the tokens of the API.
 *
 * What changes with the provider is what `AccountInterface` says. The routes
 * declare that they need a user (see `AccessRules::REQUIRES_USER`), so a visitor
 * that is not authenticated never gets here: it is sent to the login.
 */
final class AccountController
{
    /**
     * The profile, where the tokens are shown and managed (its tab of the API).
     */
    /** What the example says when the request does not say where the site is. */
    private const PLACEHOLDER_HOST = 'YOUR-SITE';

    public const PROFILE_PATH = '/auth/profile';

    /**
     * The card of the tokens, in the tab of the API: the page opens there when what
     * the user did with a token is answered (`derafu-js` reads it from the URL).
     */
    private const TOKENS_ANCHOR = '#api:tokens';

    /**
     * What every user has, in the order that the profile shows it.
     */
    private const SHOWN = ['sub', 'preferred_username', 'name', 'given_name', 'family_name', 'email', 'email_verified', 'locale'];

    public function __construct(
        private readonly RendererInterface $renderer,
        private readonly AccountInterface $account,
        private readonly FormManagerInterface $forms
    ) {
    }

    /**
     * The profile: tabs with the data of the user, the API and the session.
     */
    public function profile(ServerRequestInterface $request): string
    {
        $user = $this->user($request);
        $session = $this->session($request);

        $tokens = null;
        $tokensError = null;
        $manager = $this->account->tokens();
        if ($manager !== null) {
            try {
                $tokens = $manager->list($session);
            } catch (ProviderUnavailableException|AuthenticationException $e) {
                // The page is still of use without them: it says why they are not
                // there.
                $tokens = [];
                $tokensError = $e->getTranslatableMessage();
            }
        }

        return $this->renderer->render('auth/profile', [
            'user' => $user,
            'fields' => $this->fields($user),
            'providerFields' => $this->account->profile($user, $session),
            'otherDetails' => $this->otherDetails($user),
            'accountUrl' => $this->account->accountUrl(),
            'apiScheme' => $this->account->apiScheme(),
            'baseUrl' => $this->baseUrl($request),
            'tokens' => $tokens,
            'tokensSupported' => $manager !== null,
            'tokenForm' => $manager?->form($user),
            'tokensError' => $tokensError,
            'phpSession' => PhpSessionDetails::of($session),
            'providerSession' => $this->account->sessionDetails($session),
        ]);
    }

    /**
     * Makes a token with what the user gave in the form: it is shown in this
     * response and nowhere else (nothing keeps it, and the page is not cached). If it
     * can not be made (the password is not the user's) the user goes back to the
     * profile with the reason.
     */
    public function tokenCreate(ServerRequestInterface $request): ResponseInterface
    {
        $this->sameOrigin($request);
        $this->user($request);
        $manager = $this->manager();
        $session = $this->session($request);

        try {
            $token = $manager->create($request, $session);
        } catch (AuthenticationException|FormException $e) {
            Flash::error($request, $e->getTranslatableMessage());

            return new RedirectResponse(self::PROFILE_PATH . self::TOKENS_ANCHOR);
        }

        return new HtmlResponse(
            $this->renderer->render('auth/token-created', [
                'tokenForm' => $this->forms->createForm(new ApiTokenValueForm(), [ApiTokenValueForm::TOKEN => $token->value]),
                'token' => $token->value,
                'createdAt' => $token->createdAt,
                'expiresAt' => $token->expiresAt,
                'apiScheme' => $this->account->apiScheme(),
                'baseUrl' => $this->baseUrl($request),
            ]),
            200,
            ['Cache-Control' => 'no-store']
        );
    }

    /**
     * Revokes a token of the user, and only that one.
     */
    public function tokenRevoke(ServerRequestInterface $request, string $id): ResponseInterface
    {
        $this->sameOrigin($request);

        try {
            $this->manager()->revoke($this->session($request), $id);
            Flash::success($request, 'The token was revoked.');
        } catch (AuthenticationException $e) {
            Flash::error($request, $e->getTranslatableMessage());
        }

        return new RedirectResponse(self::PROFILE_PATH . self::TOKENS_ANCHOR);
    }

    /**
     * The user of the request.
     *
     * @throws AuthenticationException If nobody is authenticated.
     */
    private function user(ServerRequestInterface $request): UserInterface
    {
        $user = $request->getAttribute(MezzioUserInterface::class);

        if (!$user instanceof UserInterface || $user->isAnonymous()) {
            throw new AuthenticationException(
                ['You must be logged in to access the requested page {path}', 'path' => $request->getUri()->getPath()],
                401
            );
        }

        return $user;
    }

    /**
     * @throws AuthenticationException If the request has no session.
     */
    private function session(ServerRequestInterface $request): SessionInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);

        if (!$session instanceof SessionInterface) {
            throw new AuthenticationException('The request has no session.', 400);
        }

        return $session;
    }

    /**
     * @throws AuthenticationException If the provider has no tokens.
     */
    private function manager(): ApiTokenManagerInterface
    {
        return $this->account->tokens()
            ?? throw new AuthenticationException('This provider has no tokens for the API.', 404);
    }

    /**
     * A POST that changes something is only for the site itself.
     *
     * @throws AuthorizationException If it comes from another site.
     */
    private function sameOrigin(ServerRequestInterface $request): void
    {
        if (!SameOrigin::of($request)) {
            throw new AuthorizationException('The request does not come from this site.', 403);
        }
    }

    /**
     * What every user has: the ones that it does not have are not shown.
     *
     * @return list<array{label: TranslatableMessage, value: mixed}>
     */
    private function fields(UserInterface $user): array
    {
        $roles = [];
        foreach ($user->getRoles() as $role) {
            $roles[] = (string) $role;
        }

        $fields = [
            ['label' => new TranslatableMessage('Identity', [], 'auth'), 'value' => $user->getIdentity()],
            ['label' => new TranslatableMessage('Username', [], 'auth'), 'value' => $user->getUsername()],
            ['label' => new TranslatableMessage('Name', [], 'auth'), 'value' => $user->getName()],
            ['label' => new TranslatableMessage('Email', [], 'auth'), 'value' => $user->getEmail()],
            ['label' => new TranslatableMessage('Email verified', [], 'auth'), 'value' => $user->getEmail() !== null ? $user->isEmailVerified() : null],
            ['label' => new TranslatableMessage('Language', [], 'auth'), 'value' => $user->getLocale()],
            ['label' => new TranslatableMessage('Roles', [], 'auth'), 'value' => $roles !== [] ? $roles : null],
        ];

        return array_values(array_filter($fields, fn (array $field) => $field['value'] !== null));
    }

    /**
     * The details of the user that are not the ones that the profile shows (the
     * claims that a mapper of the realm adds, an attribute).
     *
     * @return array<string, mixed>
     */
    private function otherDetails(UserInterface $user): array
    {
        return array_diff_key($user->getDetails(), array_flip(self::SHOWN));
    }

    /**
     * The address of the site, for the example of the call to the API: the one that
     * the provider knows, or else the one of the request. The URI of a request is
     * only its path in the runtime of the HTTP package, so the host is the header
     * `Host` and the scheme is the one of the connection.
     */
    private function baseUrl(ServerRequestInterface $request): string
    {
        $known = $this->account->publicUrl();
        if ($known !== null) {
            return $known;
        }

        $uri = $request->getUri();
        $host = $uri->getHost() !== '' ? $uri->getAuthority() : $request->getHeaderLine('Host');
        if ($host === '') {
            return 'https://' . self::PLACEHOLDER_HOST;
        }

        $https = ($request->getServerParams()['HTTPS'] ?? 'off') !== 'off' && ($request->getServerParams()['HTTPS'] ?? '') !== '';
        $scheme = $uri->getScheme() !== '' ? $uri->getScheme() : ($https ? 'https' : 'http');

        return $scheme . '://' . $host;
    }
}
