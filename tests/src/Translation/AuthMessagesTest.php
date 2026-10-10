<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Translation;

use Derafu\Auth\Authentication\Channel\Web\Flash;
use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Form\Lint\FormTranslationAudit;
use Derafu\Translation\Lint\MessageMethod;
use Derafu\Translation\Lint\MessageReference;
use Derafu\Twig\Lint\TwigTranslationAudit;
use Derafu\Twig\Service\TwigService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * The package is translated: every message of its code and of its templates has
 * its Spanish translation, the catalogue has nothing that they do not use, every
 * text of the templates goes through the translation, and every exception that
 * the package throws is translatable.
 *
 * It is found by reading the code and the templates, so a new message without an
 * entry in the catalogue fails here, instead of showing in the original language
 * when it is shown.
 *
 * Two messages can not be literals, by nature, and they are fixed here by their
 * function and their whole call, so any other message that is not a literal makes
 * this test fail:
 *
 *   - The flash message of a form that is not valid is the message of the
 *     exception of the form: it is given as it is, and it is audited where the
 *     exception is thrown.
 *   - When the form has an error of its own (a CSRF token that is not valid),
 *     the exception has the text of that error: it is audited in derafu/form,
 *     where it is written.
 *   - The partial of the flash messages translates the message that it is given
 *     (its id, parameters and domain are data of the session).
 */
#[CoversClass(AuthTranslationResourceProvider::class)]
final class AuthMessagesTest extends TestCase
{
    public function testThePackageIsTranslated(): void
    {
        $root = dirname(__DIR__, 3);

        // The templates are written for an application that has routes, forms
        // and a layout: the functions that they use are only declared here.
        $application = new class () extends AbstractExtension {
            public function getFunctions(): array
            {
                return array_map(
                    fn (string $name) => new TwigFunction($name, fn () => ''),
                    ['path', 'form_start', 'form_element', 'form_captcha', 'form_csrf', 'form_end', 'is_granted', 'login_path', 'logout_path', 'profile_path']
                );
            }
        };

        $report = (new TwigTranslationAudit())->audit(
            $root . '/src',
            $root . '/resources/templates',
            new AuthTranslationResourceProvider(),
            (new TwigService([
                'extra' => false,
                'paths' => [$root . '/resources/templates', $root . '/vendor/derafu/twig/resources/templates'],
                'extensions' => [$application],
            ]))->getTwig(),
            messageMethods: [
                new MessageMethod(Flash::class, 'error', domain: 'auth', id: 1),
                new MessageMethod(Flash::class, 'success', domain: 'auth', id: 1),
            ],
            // The examples of a call to the API are code, not prose: they are not
            // translated.
            allowedTexts: [
                'curl -u USERNAME:PASSWORD /api/...',
                'curl -H "Authorization: Bearer TOKEN" /api/...',
                'curl -H "Authorization: TOKEN" /api/...',
            ]
        );

        // Finding nothing would look like a clean result.
        $this->assertFalse($report->nothingFound);
        $this->assertSame([], $report->describe($report->missingTranslations));

        // The texts of the login form are in the same domain as the ones of the
        // templates, so the audit of the templates sees them as not used: they
        // are the ones that the audit of the form finds.
        $usedByTheForms = [];
        foreach (['/src/Provider/Database/Web/Form', '/src/Provider/Keycloak/Account/Form', '/src/Account/Form'] as $directory) {
            $forms = (new FormTranslationAudit())->audit($root . $directory, new AuthTranslationResourceProvider());
            $this->assertFalse($forms->nothingFound, $directory);
            $this->assertSame([], $forms->describe($forms->dynamicTexts), $directory);
            $this->assertSame([], $forms->describe($forms->withoutDomain), $directory);
            $this->assertSame([], $forms->describe($forms->missingTranslations), $directory);

            foreach ($forms->texts as $text) {
                $usedByTheForms[] = ['domain' => (string) $text->domain, 'id' => (string) $text->id];
            }
        }
        $this->assertSame(
            [],
            $report->describe(array_values(array_filter(
                $report->notUsedBySources,
                fn (array $entry) => !in_array($entry, $usedByTheForms, true)
            )))
        );
        $this->assertSame([], $report->describe($report->notTranslatable));
        $this->assertSame([], $report->describe($report->untranslatedTexts));

        $this->assertSame(
            [
                'Derafu\\Auth\\Account\\AccountController::tokenCreate: '
                    . '\\Derafu\\Auth\\Authentication\\Channel\\Web\\Flash::error($request, $e->getTranslatableMessage())',
                'Derafu\\Auth\\Account\\AccountController::tokenRevoke: '
                    . '\\Derafu\\Auth\\Authentication\\Channel\\Web\\Flash::error($request, $e->getTranslatableMessage())',
                'Derafu\\Auth\\Authentication\\Channel\\Web\\Flash::message: '
                    . 'new \\Derafu\\Translation\\TranslatableMessage($message, $parameters, \'auth\')',
                'Derafu\\Auth\\Authentication\\Channel\\Web\\FormManager::processForm: '
                    . 'new \\Derafu\\Auth\\Exception\\FormException($formError, 400)',
                'Derafu\\Auth\\Provider\\Database\\Web\\DatabaseWebFlow::login: '
                    . '\\Derafu\\Auth\\Authentication\\Channel\\Web\\Flash::error($request, $e->getTranslatableMessage(), now: true)',
                'Derafu\\Auth\\Provider\\Htpasswd\\Web\\HtpasswdWebFlow::login: '
                    . '\\Derafu\\Auth\\Authentication\\Channel\\Web\\Flash::error($request, $e->getTranslatableMessage(), now: true)',
                // The reason that a client of the API is told (`error_description`): a few
                // texts in English, as the RFC wants them, that are not translated.
                'Derafu\\Auth\\Provider\\Keycloak\\Api\\KeycloakBearerScheme::authenticateToken: new \\Derafu\\Auth\\Exception\\AuthenticationException(self::reasonOf($e), 401, $e)',
                'auth/profile/_macros.html.twig: <th scope="row" class="w-25">{{ field.label|trans }}</th>',
                'auth/profile/_session.html.twig: <div class="card-header">{{ section.title|trans }}</div>',
                'auth/profile/_tokens.html.twig: <div class="alert alert-warning small" role="alert">{{ tokensError|trans }}</div>',
                'partials/flash-messages.html.twig: '
                    . '{% set text = message.message|trans(parameters, message.domain ?? null) %}',
            ],
            array_map(fn (MessageReference $reference) => $reference->identity(), $report->dynamicMessages)
        );
    }
}
