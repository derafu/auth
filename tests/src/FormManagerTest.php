<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth;

use Derafu\Auth\Exception\FormException;
use Derafu\Auth\FormManager;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\Form\LoginForm;
use Derafu\Csrf\SessionCsrfTokenManager;
use Derafu\DataProcessor\ProcessorFactory;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Processor\FormDataProcessor;
use Derafu\Form\Processor\FormRulesResolver;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The forms of the authentication are created and processed with the real form
 * and data processor.
 */
#[CoversClass(FormManager::class)]
#[UsesClass(LoginForm::class)]
#[UsesClass(DatabaseConfiguration::class)]
#[UsesClass(\Derafu\Auth\Abstract\AbstractProviderConfiguration::class)]
#[UsesClass(FormException::class)]
final class FormManagerTest extends TestCase
{
    private SessionCsrfTokenManager $csrf;

    protected function setUp(): void
    {
        $this->csrf = new SessionCsrfTokenManager();
        $this->csrf->useSession(new Session([]));
    }

    /**
     * The data of a form that is sent, with the token of its session.
     *
     * @param array<string, string> $data
     * @return array<string, string>
     */
    private function sent(array $data): array
    {
        return $data + ['_token' => $this->csrf->getToken('login')];
    }

    /**
     * @param array<string, mixed> $config
     */
    private function manager(array $config = []): FormManager
    {
        return new FormManager(
            new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
            new FormDataProcessor(new FormRulesResolver(), (new ProcessorFactory())->create(), csrfTokenManager: $this->csrf),
            new DatabaseConfiguration($config + ['database_url' => 'sqlite::memory:'])
        );
    }

    #[Test]
    public function createsTheFormOfAType(): void
    {
        $form = $this->manager()->createForm(LoginForm::class);

        $this->assertSame(['email', 'password'], array_keys($form->getFields()));
        $this->assertNull($form->getData());
    }

    #[Test]
    public function theFieldsAreTheOnesOfTheConfiguration(): void
    {
        $form = $this->manager(['user_repository' => ['field' => ['identity' => 'rut', 'password' => 'clave']]])
            ->createForm(LoginForm::class);

        $this->assertSame(['rut', 'clave'], array_keys($form->getFields()));
    }

    #[Test]
    public function createsTheFormWithTheData(): void
    {
        $form = $this->manager()->createForm(LoginForm::class, ['email' => 'ana@example.com']);

        $this->assertSame(['email' => 'ana@example.com'], $form->getData()?->toArray());
    }

    #[Test]
    public function processesTheValidData(): void
    {
        $result = $this->manager()->processForm(
            LoginForm::class,
            $this->sent(['email' => 'ana@example.com', 'password' => 'secret'])
        );

        $this->assertTrue($result->isValid());
        $this->assertSame(
            ['email' => 'ana@example.com', 'password' => 'secret'],
            $result->getProcessedData()
        );
    }

    #[Test]
    public function theDataThatIsNotInTheFormIsKept(): void
    {
        $result = $this->manager()->processForm(
            LoginForm::class,
            $this->sent(['email' => 'ana@example.com', 'password' => 'secret', 'remember' => 'on'])
        );

        $this->assertSame('on', $result->getProcessedData()['remember']);
    }

    #[Test]
    public function invalidDataIsAnErrorWithTheCode400(): void
    {
        try {
            $this->manager()->processForm(LoginForm::class, $this->sent(['email' => 'ana@example.com']));
            $this->fail('It should have failed.');
        } catch (FormException $e) {
            $this->assertSame(400, $e->getCode());
            $this->assertSame('Invalid form data.', $e->getMessage());
        }
    }

    #[Test]
    public function aFormSentWithoutTheTokenIsRejectedWithTheMessageOfTheForm(): void
    {
        try {
            $this->manager()->processForm(LoginForm::class, ['email' => 'ana@example.com', 'password' => 'secret']);
            $this->fail('It should have failed.');
        } catch (FormException $e) {
            $this->assertSame(400, $e->getCode());
            $this->assertSame('The form is not valid or has expired. Reload the page and try again.', $e->getMessage());
        }
    }

    #[Test]
    public function aTokenThatIsNotTheOneOfTheFormIsRejected(): void
    {
        $this->csrf->getToken('login');

        $this->expectException(FormException::class);
        $this->expectExceptionMessage('The form is not valid or has expired.');

        $this->manager()->processForm(
            LoginForm::class,
            ['email' => 'ana@example.com', 'password' => 'secret', '_token' => $this->csrf->getToken('contact')]
        );
    }

    #[Test]
    public function noDataIsInvalid(): void
    {
        $this->expectException(FormException::class);

        $this->manager()->processForm(LoginForm::class, []);
    }
}
