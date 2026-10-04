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

use Derafu\Auth\Translation\AuthTranslationResourceProvider;
use Derafu\Translation\Lint\MessageReference;
use Derafu\Translation\Lint\MessageReferenceScanner;
use Derafu\Translation\TranslatorFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Translation\MessageCatalogueInterface;

/**
 * Every message of the package has a Spanish translation, and the catalogue has
 * nothing the code does not use.
 *
 * The messages are found by reading the code, so a new message without an entry
 * in the catalogue fails here, instead of showing in the original language when
 * the error happens.
 */
#[CoversClass(AuthTranslationResourceProvider::class)]
final class AuthMessagesTest extends TestCase
{
    private function catalogue(): MessageCatalogueInterface
    {
        return TranslatorFactory::create('es', [], [new AuthTranslationResourceProvider()])
            ->getCatalogue('es')
        ;
    }

    /**
     * @return list<MessageReference>
     */
    private function references(): array
    {
        $references = (new MessageReferenceScanner())->scanDirectory(dirname(__DIR__, 3) . '/src');

        $references = array_values(array_filter($references, fn (MessageReference $r) => $r->id !== ''));

        // Finding nothing would look like a clean result.
        $this->assertNotEmpty($references);

        return $references;
    }

    public function testEveryMessageIsALiteralThatCanBeChecked(): void
    {
        $dynamic = array_map(
            fn (MessageReference $r) => sprintf('%s:%d', $r->file, $r->line),
            array_filter($this->references(), fn (MessageReference $r) => $r->isDynamic())
        );

        $this->assertSame([], array_values($dynamic));
    }

    public function testEveryMessageHasATranslation(): void
    {
        $catalogue = $this->catalogue();

        $missing = [];
        foreach ($this->references() as $reference) {
            if (!$reference->isDynamic() && !$catalogue->has((string) $reference->id, (string) $reference->domain)) {
                $missing[] = sprintf('%s [%s] (%s:%d)', $reference->id, $reference->domain, basename($reference->file), $reference->line);
            }
        }

        $this->assertSame([], $missing);
    }

    public function testTheCatalogueHasNoMessageThatTheCodeDoesNotUse(): void
    {
        $used = [];
        foreach ($this->references() as $reference) {
            $used[$reference->domain][] = $reference->id;
        }

        $catalogue = $this->catalogue();
        $unused = [];
        foreach ($catalogue->getDomains() as $domain) {
            foreach (array_diff(array_keys($catalogue->all($domain)), $used[$domain] ?? []) as $id) {
                $unused[] = sprintf('%s [%s]', $id, $domain);
            }
        }

        $this->assertSame([], $unused);
    }
}
