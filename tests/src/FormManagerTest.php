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

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\Payload;
use AltchaOrg\Altcha\SolveChallengeOptions;
use Derafu\Auth\Authentication\Channel\Web\FormManager;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Exception\FormException;
use Derafu\Auth\Provider\Database\DatabaseConfiguration;
use Derafu\Auth\Provider\Database\Web\Form\LoginForm;
use Derafu\Captcha\Provider\AltchaProvider;
use Derafu\Csrf\SessionCsrfTokenManager;
use Derafu\DataProcessor\Contract\ProcessorInterface;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Factory\FormFactory;
use Derafu\Form\Processor\FormDataProcessor;
use Derafu\Form\Processor\FormRulesResolver;
use Derafu\Form\Type\TypeProvider;
use Derafu\Form\Type\TypeRegistry;
use Derafu\Form\Type\TypeResolver;
use Derafu\TestsAuth\Fixture\AuthApplication;
use Derafu\TestsAuth\Fixture\Stack;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\Attributes\UsesNamespace;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use stdClass;
use Symfony\Component\DependencyInjection\ServiceLocator;

/**
 * The forms of the authentication are created and processed with the real form
 * and data processor.
 */
#[CoversClass(FormManager::class)]
#[UsesClass(LoginForm::class)]
#[UsesClass(DatabaseConfiguration::class)]
#[UsesClass(FormException::class)]
#[UsesNamespace('Derafu\\Auth')]
final class FormManagerTest extends TestCase
{
    private SessionCsrfTokenManager $csrf;

    private AltchaProvider $captcha;

    protected function setUp(): void
    {
        $this->csrf = new SessionCsrfTokenManager();
        $this->csrf->useSession(new Session([]));
        $this->captcha = new AltchaProvider('a-secret-key', 'en', cost: 10);
    }

    /**
     * What the visitor sends when it solves the captcha of a form: the browser
     * solves the challenge of the widget, which is done here with the library.
     */
    private function solved(string $formId = 'login'): string
    {
        preg_match('/ challenge="([^"]*)"/', $this->captcha->getWidget($formId), $matches);
        $this->assertTrue(isset($matches[1]));
        $data = json_decode(html_entity_decode($matches[1], ENT_QUOTES), true);
        $this->assertIsArray($data);
        $decoded = [];
        foreach ($data as $key => $value) {
            $this->assertIsString($key);
            $decoded[$key] = $value;
        }
        $challenge = Challenge::fromArray($decoded);
        $solution = (new Altcha(hmacSignatureSecret: 'a-secret-key'))->solveChallenge(new SolveChallengeOptions(
            algorithm: new Pbkdf2(),
            challenge: $challenge,
        ));
        $this->assertNotNull($solution, 'The challenge was not solved.');

        return (new Payload($challenge, $solution))->toBase64();
    }

    /**
     * The data of a form that is sent, with the token of its session and what the
     * visitor solved of the captcha.
     *
     * @param array<string, string> $data
     * @return array<string, string>
     */
    private function sent(array $data, bool $captcha = true): array
    {
        $data += [FormInterface::CSRF_FIELD => $this->csrf->getToken('login')];

        return $captcha ? $data + ['altcha' => $this->solved()] : $data;
    }

    /**
     * @param array<string, mixed> $config
     */
    private function manager(array $config = [], ?ContainerInterface $definitions = null): FormManager
    {
        return new FormManager(
            new FormFactory(new TypeResolver(new TypeRegistry(new TypeProvider()))),
            new FormDataProcessor(new FormRulesResolver(), AuthApplication::service(ProcessorInterface::class), csrfTokenManager: $this->csrf, captchaProvider: $this->captcha),
            $definitions ?? Stack::formDefinitions(Stack::databaseConfiguration($config + ['database_url' => 'sqlite::memory:']))
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
    public function theDataThatIsNotInTheFormIsDropped(): void
    {
        $result = $this->manager()->processForm(
            LoginForm::class,
            $this->sent(['email' => 'ana@example.com', 'password' => 'secret', 'remember' => 'on'])
        );

        $this->assertSame(
            ['email' => 'ana@example.com', 'password' => 'secret'],
            $result->getProcessedData()
        );
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
    public function aFormSentWithoutTheCaptchaIsRejectedWithTheMessageOfTheForm(): void
    {
        try {
            $this->manager()->processForm(
                LoginForm::class,
                $this->sent(['email' => 'ana@example.com', 'password' => 'secret'], captcha: false)
            );
            $this->fail('It should have failed.');
        } catch (FormException $e) {
            $this->assertSame(400, $e->getCode());
            $this->assertSame('The captcha is not valid. Try again.', $e->getMessage());
        }
    }

    #[Test]
    public function theCaptchaOfAnotherFormIsRejected(): void
    {
        $this->expectException(FormException::class);
        $this->expectExceptionMessage('The captcha is not valid. Try again.');

        $this->manager()->processForm(
            LoginForm::class,
            $this->sent(['email' => 'ana@example.com', 'password' => 'secret', 'altcha' => $this->solved('contact')], captcha: false)
        );
    }

    #[Test]
    public function aTokenThatIsNotTheOneOfTheFormIsRejected(): void
    {
        $this->csrf->getToken('login');

        $this->expectException(FormException::class);
        $this->expectExceptionMessage('The form is not valid or has expired.');

        $this->manager()->processForm(
            LoginForm::class,
            ['email' => 'ana@example.com', 'password' => 'secret', FormInterface::CSRF_FIELD => $this->csrf->getToken('contact')]
        );
    }

    #[Test]
    public function noDataIsInvalid(): void
    {
        $this->expectException(FormException::class);

        $this->manager()->processForm(LoginForm::class, []);
    }

    #[Test]
    public function anObjectFormDefinitionReceivesItsInitialData(): void
    {
        $definition = new LoginForm(Stack::databaseConfiguration(['database_url' => 'sqlite::memory:']));
        $form = $this->manager()->createForm($definition, ['email' => 'ana@example.com']);

        $this->assertSame(['email', 'password'], array_keys($form->getFields()));
        $this->assertSame(['email' => 'ana@example.com'], $form->getData()?->toArray());
    }

    #[Test]
    public function anUnregisteredFormReportsHowToRegisterIt(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The authentication form "' . LoginForm::class . '" is not registered. Register its service with the derafu_auth.form tag.');

        $this->manager(definitions: new ServiceLocator([]))->createForm(LoginForm::class);
    }

    #[Test]
    public function aRegisteredServiceMustImplementTheFormContract(): void
    {
        $locator = new ServiceLocator([LoginForm::class => static fn (): stdClass => new stdClass()]);
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('received stdClass.');

        $this->manager(definitions: $locator)->createForm(LoginForm::class);
    }

    #[Test]
    public function definitionsAreLazyAndReusedWithoutSharingPerCallData(): void
    {
        $constructions = 0;
        $locator = new ServiceLocator([
            LoginForm::class => static function () use (&$constructions): LoginForm {
                ++$constructions;

                return new LoginForm(Stack::databaseConfiguration(['database_url' => 'sqlite::memory:']));
            },
        ]);
        $manager = $this->manager(definitions: $locator);
        self::assertSame(0, $constructions);
        $first = $manager->createForm(LoginForm::class, ['email' => 'ana@example.com']);
        $second = $manager->createForm(LoginForm::class, ['email' => 'bob@example.com']);
        $empty = $manager->createForm(LoginForm::class);

        self::assertSame(1, $constructions);
        self::assertNotSame($first, $second);
        self::assertSame(['email' => 'ana@example.com'], $first->getData()?->toArray());
        self::assertSame(['email' => 'bob@example.com'], $second->getData()?->toArray());
        self::assertNull($empty->getData());
    }

    #[Test]
    public function aSuppliedDefinitionDoesNotRequireRegistration(): void
    {
        $definition = new LoginForm(Stack::databaseConfiguration([
            'database_url' => 'sqlite::memory:',
            'user_repository' => ['field' => ['identity' => 'rut', 'password' => 'clave']],
        ]));
        $form = $this->manager(definitions: new ServiceLocator([]))->createForm($definition, ['rut' => '123']);

        self::assertSame(['rut', 'clave'], array_keys($form->getFields()));
        self::assertSame(['rut' => '123'], $form->getData()?->toArray());
    }
}
