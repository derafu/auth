<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Exception;

use Closure;
use Derafu\Auth\Exception\AuthenticationException;
use Derafu\Auth\Exception\AuthorizationException;
use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Exception\FormException;
use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Translation\Exception\Core\TranslatableException;
use Exception;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The exceptions of the package can be translated, and keep their code and
 * their previous exception.
 */
#[CoversClass(AuthenticationException::class)]
#[CoversClass(AuthorizationException::class)]
#[CoversClass(ConfigurationException::class)]
#[CoversClass(FormException::class)]
final class AuthExceptionsTest extends TestCase
{
    /**
     * @return array<string, array{Closure(mixed ...): TranslatableException}>
     */
    public static function exceptionsProvider(): array
    {
        return [
            'authentication' => [fn (mixed ...$arguments) => new AuthenticationException(...$arguments)],
            'authorization' => [fn (mixed ...$arguments) => new AuthorizationException(...$arguments)],
            'configuration' => [fn (mixed ...$arguments) => new ConfigurationException(...$arguments)],
            'form' => [fn (mixed ...$arguments) => new FormException(...$arguments)],
        ];
    }

    /**
     * @param Closure(mixed ...): TranslatableException $create
     */
    #[DataProvider('exceptionsProvider')]
    public function testEveryExceptionIsTranslatable(Closure $create): void
    {
        $previous = new Exception('Previous.');
        $exception = $create('Failed.', 400, $previous);

        $this->assertInstanceOf(Exception::class, $exception);
        $this->assertInstanceOf(TranslatableInterface::class, $exception);
        $this->assertSame('Failed.', $exception->getMessage());
        $this->assertSame(400, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    /**
     * @param Closure(mixed ...): TranslatableException $create
     */
    #[DataProvider('exceptionsProvider')]
    public function testTheMessageCanBeGivenWithNamedParameters(Closure $create): void
    {
        $exception = $create(['Failed because {reason}.', 'reason' => 'it is late']);

        $this->assertSame('Failed because it is late.', $exception->getMessage());
    }

    /**
     * @param Closure(mixed ...): TranslatableException $create
     */
    #[DataProvider('exceptionsProvider')]
    public function testItCanBeCreatedWithoutAMessage(Closure $create): void
    {
        $this->assertSame('', $create()->getMessage());
    }
}
