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

use Derafu\Auth\Abstract\AbstractProviderAuthentication;
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
                    ['path', 'form_start', 'form_element', 'form_captcha', 'form_csrf', 'form_end']
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
                new MessageMethod(AbstractProviderAuthentication::class, 'addErrorFlash', domain: 'auth', id: 1),
                new MessageMethod(AbstractProviderAuthentication::class, 'addSuccessFlash', domain: 'auth', id: 1),
            ]
        );

        // Finding nothing would look like a clean result.
        $this->assertFalse($report->nothingFound);
        $this->assertSame([], $report->describe($report->missingTranslations));

        // The texts of the login form are in the same domain as the ones of the
        // templates, so the audit of the templates sees them as not used: they
        // are the ones that the audit of the form finds.
        $forms = (new FormTranslationAudit())->audit(
            $root . '/src/Provider/Database/Form',
            new AuthTranslationResourceProvider()
        );
        $this->assertFalse($forms->nothingFound);
        $this->assertSame([], $forms->describe($forms->dynamicTexts));
        $this->assertSame([], $forms->describe($forms->withoutDomain));
        $this->assertSame([], $forms->describe($forms->missingTranslations));

        $usedByTheForms = array_map(
            fn ($text) => ['domain' => (string) $text->domain, 'id' => (string) $text->id],
            $forms->texts
        );
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
                'Derafu\\Auth\\FormManager::processForm: '
                    . 'new \\Derafu\\Auth\\Exception\\FormException($formError, 400)',
                'Derafu\\Auth\\Provider\\Database\\DatabaseAuthentication::handleLogin: '
                    . '$this->addErrorFlash($request, $e->getTranslatableMessage(), now: true)',
                'Derafu\\Auth\\Provider\\Htpasswd\\HtpasswdAuthentication::handleLogin: '
                    . '$this->addErrorFlash($request, $e->getTranslatableMessage(), now: true)',
                'partials/flash-messages.html.twig: '
                    . '{% set text = message.message|trans(parameters, message.domain ?? null) %}',
            ],
            array_map(fn (MessageReference $reference) => $reference->identity(), $report->dynamicMessages)
        );
    }
}
