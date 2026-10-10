<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Auth\Provider\Keycloak\Account;

use Derafu\Auth\Account\ApiToken;
use Derafu\Auth\Account\NewApiToken;
use Derafu\Auth\Contract\ApiTokenManagerInterface;
use Derafu\Auth\Contract\FormManagerInterface;
use Derafu\Auth\Contract\UserInterface;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\ProviderUnavailableException;
use Derafu\Auth\Provider\Keycloak\Account\Form\ApiTokenForm;
use Derafu\Auth\Provider\Keycloak\KeycloakUserRepository;
use Derafu\Auth\Provider\Keycloak\TokenClaims;
use Derafu\Auth\Provider\Keycloak\Web\KeycloakSessionManager;
use Derafu\Form\Contract\FormInterface;
use Derafu\Translation\TranslatableMessage;
use Mezzio\Authentication\UserInterface as MezzioUserInterface;
use Mezzio\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The tokens of the API of Keycloak: as many as the user wants, each one an offline
 * session that it can revoke by itself.
 */
class KeycloakApiTokenManager implements ApiTokenManagerInterface
{
    public function __construct(
        private readonly KeycloakUserRepository $userRepository,
        private readonly KeycloakAccountClient $account,
        private readonly KeycloakSessionManager $sessionManager,
        private readonly FormManagerInterface $formManager,
        private readonly ?TranslatorInterface $translator = null
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function list(SessionInterface $session): array
    {
        return $this->account->tokens($this->accessToken($session));
    }

    /**
     * {@inheritDoc}
     */
    public function form(UserInterface $user, array $data = []): FormInterface
    {
        $help = new TranslatableMessage(
            'It is the password of the user <code>{username}</code> in the realm <code>{realm}</code>. If you log in through another provider (identity brokering), you must first create a password for that user in the realm <code>{realm}</code>.',
            // The text is shown as HTML (it has the tags of the variables): what
            // comes from the user and from the configuration is escaped here.
            ['username' => htmlspecialchars($user->getUsername() ?? $user->getIdentity()), 'realm' => htmlspecialchars($this->userRepository->getRealm())],
            'auth'
        );

        return $this->formManager->createForm(
            (new ApiTokenForm())->withHelp($this->translator !== null ? $help->trans($this->translator) : (string) $help),
            $data
        );
    }

    /**
     * {@inheritDoc}
     *
     * The user gives its password again, and Keycloak makes the token as a session of
     * its own. The token must be of the user of the session: what the password opens
     * is checked, not taken for granted.
     */
    public function create(ServerRequestInterface $request, SessionInterface $session): NewApiToken
    {
        $user = $request->getAttribute(MezzioUserInterface::class);
        if (!$user instanceof UserInterface || $user->isAnonymous()) {
            throw new AuthenticationException('There is no user in the session.', 401);
        }

        // The form checks what came (its CSRF token, the password that is there).
        $body = $request->getParsedBody();
        $data = $this->formManager->processForm(ApiTokenForm::class, is_array($body) ? $body : [])->getProcessedData();
        $password = (string) $data[ApiTokenForm::PASSWORD];
        $otp = is_string($data[ApiTokenForm::TOTP] ?? null) ? trim($data[ApiTokenForm::TOTP]) : null;

        try {
            $answer = $this->userRepository->requestOfflineToken(
                $user->getUsername() ?? $user->getIdentity(),
                $password,
                $otp
            );
        } catch (AuthenticationException $e) {
            throw $e->getCode() === 401 ? $this->whyTheCredentialsAreNotValid($session, $otp !== null && $otp !== '', $e) : $e;
        }

        $token = (string) $answer['refresh_token'];
        $claims = TokenClaims::of($token);
        if (($claims['sub'] ?? null) !== $user->getIdentity()) {
            throw new AuthenticationException('The token is not for the user of this session.', 400);
        }

        // When it was made and when it ends are what the token says (Keycloak gives an
        // end to the ones that it makes, and not every version does).
        return new NewApiToken(
            $token,
            isset($claims['iat']) ? (int) $claims['iat'] : null,
            isset($claims['exp']) ? (int) $claims['exp'] : null
        );
    }

    /**
     * Keycloak says the same when the password is not valid, when the code of the
     * second factor is not valid and when it is missing. The user is in its session,
     * so what is known of it can be used to say what is more likely: if the user has a
     * second factor, the code is part of what can be wrong.
     */
    private function whyTheCredentialsAreNotValid(SessionInterface $session, bool $sentCode, AuthenticationException $e): AuthenticationException
    {
        try {
            $hasSecondFactor = $this->account->hasSecondFactor($this->accessToken($session));
        } catch (AuthenticationException|ProviderUnavailableException) {
            // It is not known (Keycloak did not say): the code is what was sent.
            $hasSecondFactor = $sentCode;
        }

        if (!$hasSecondFactor) {
            return $e;
        }

        return $sentCode
            ? new AuthenticationException('The password or the code of the second factor is not valid.', 401, $e)
            : new AuthenticationException('The password is not valid, or the code of the second factor is missing (your user has one).', 401, $e);
    }

    /**
     * {@inheritDoc}
     *
     * Only a session that is a token of the user can be revoked: not its session of
     * login, nor one that is not its own.
     */
    public function revoke(SessionInterface $session, string $id): void
    {
        $accessToken = $this->accessToken($session);

        $mine = array_filter(
            $this->account->tokens($accessToken),
            fn (ApiToken $token) => $token->id === $id
        );
        if ($mine === []) {
            throw new AuthenticationException('The user has no such token.', 404);
        }

        $this->account->revoke($accessToken, $id);
    }

    /**
     * @throws AuthenticationException If the session has no access token.
     */
    private function accessToken(SessionInterface $session): string
    {
        return $this->sessionManager->getAccessToken($session)
            ?? throw new AuthenticationException('There is no session with Keycloak.', 401);
    }
}
