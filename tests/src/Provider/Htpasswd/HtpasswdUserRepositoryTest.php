<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Provider\Htpasswd;

use Derafu\Auth\Exception\ConfigurationException;
use Derafu\Auth\Provider\Htpasswd\HtpasswdConfiguration;
use Derafu\Auth\Provider\Htpasswd\HtpasswdUserRepository;
use Derafu\Auth\User;
use Derafu\Auth\UserFactory;
use Derafu\TestsAuth\Fixture\CustomUser;
use Derafu\TestsAuth\Fixture\CustomUserFactory;
use Derafu\TestsAuth\Fixture\HtpasswdFile;
use Derafu\TestsAuth\Fixture\Stack;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The users of an `.htpasswd` file: only who they are, only with bcrypt, and the
 * file is the one that says it every time.
 */
#[CoversClass(HtpasswdUserRepository::class)]
#[CoversClass(HtpasswdConfiguration::class)]
#[UsesClass(User::class)]
#[UsesClass(UserFactory::class)]
#[UsesClass(ConfigurationException::class)]
final class HtpasswdUserRepositoryTest extends TestCase
{
    private HtpasswdFile $file;

    protected function setUp(): void
    {
        $this->file = new HtpasswdFile(['ana' => 'secret', 'beto' => 'other']);
    }

    protected function tearDown(): void
    {
        $this->file->remove();
    }

    private function repository(): HtpasswdUserRepository
    {
        return new HtpasswdUserRepository($this->file->config());
    }

    #[Test]
    public function theRightPasswordGivesAUserWithOnlyItsIdentity(): void
    {
        $user = $this->repository()->authenticate('ana', 'secret');

        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('ana', $user->getIdentity());
        $this->assertSame([], $user->getRoles());
        $this->assertSame([], $user->getDetails());
    }

    #[Test]
    public function aWrongPasswordAnUnknownUserAndNoPasswordGiveNoUser(): void
    {
        $repository = $this->repository();

        $this->assertNull($repository->authenticate('ana', 'wrong'));
        $this->assertNull($repository->authenticate('ana', 'other'));
        $this->assertNull($repository->authenticate('ana', null));
        $this->assertNull($repository->authenticate('nobody', 'secret'));
        $this->assertNull($repository->authenticate('nobody', null));
    }

    #[Test]
    public function theThreeVersionsOfBcryptAreAccepted(): void
    {
        $hash = password_hash('secret', PASSWORD_BCRYPT);
        foreach (['2a', '2b', '2y'] as $version) {
            $this->file->append('user' . $version . ':$' . $version . '$' . substr($hash, 4));
        }

        $repository = $this->repository();
        foreach (['2a', '2b', '2y'] as $version) {
            $this->assertSame('user' . $version, $repository->authenticate('user' . $version, 'secret')?->getIdentity());
        }
    }

    #[Test]
    public function theLinesThatAreNotBcryptCommentsOrBlankAreIgnored(): void
    {
        // Hashes that crypt() could verify too: they are not let in.
        $this->file->append('apache:$apr1$abcdefgh$pHkOvVShUPjrbyrHK2oXP.');
        $this->file->append('sha:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=');
        $this->file->append('md5:$1$abcdefgh$jNHdCpsOTBwDDpD1zlNPD.');
        $this->file->append('old:$2x$' . substr(password_hash('secret', PASSWORD_BCRYPT), 4));
        $this->file->append('# comment:$2y$10$' . str_repeat('a', 53));
        $this->file->append('');
        $this->file->append('without-colon');

        $repository = $this->repository();

        foreach (['apache', 'sha', 'md5', 'old', '# comment', 'without-colon'] as $identity) {
            $this->assertNull($repository->find($identity), $identity);
        }
        $this->assertNull($repository->authenticate('md5', 'secret'));
        $this->assertSame('ana', $repository->find('ana')?->getIdentity());
    }

    #[Test]
    public function aFileThatWasMadeByAToolOutsideOfThePackageIsRead(): void
    {
        // Two users created with a tool of the web that makes `.htpasswd` files.
        $repository = new HtpasswdUserRepository(Stack::htpasswdConfiguration([
            'htpasswd_path' => dirname(__DIR__, 3) . '/fixtures/htpasswd/admin_user.htpasswd',
        ]));

        $this->assertSame('admin', $repository->authenticate('admin', 'i_love_derafu')?->getIdentity());
        $this->assertSame('user', $repository->authenticate('user', 'i_love_derafu_too')?->getIdentity());
        $this->assertNull($repository->authenticate('admin', 'i_love_derafu_too'));
        $this->assertNull($repository->authenticate('user', 'i_love_derafu'));
    }

    #[Test]
    public function aPasswordThatHasAColonIsVerifiedWhole(): void
    {
        $this->file->write(['ana' => 'se:cret']);

        $this->assertNotNull($this->repository()->authenticate('ana', 'se:cret'));
        $this->assertNull($this->repository()->authenticate('ana', 'se'));
    }

    #[Test]
    public function findGivesTheUsersThatAreInTheFileWithoutAPassword(): void
    {
        $repository = $this->repository();

        $this->assertSame('beto', $repository->find('beto')?->getIdentity());
        $this->assertNull($repository->find('nobody'));
    }

    #[Test]
    public function aChangeInTheFileIsWhatTheNextCallSees(): void
    {
        $repository = $this->repository();
        $this->assertNotNull($repository->find('ana'));

        $this->file->write(['beto' => 'other']);

        $this->assertNull($repository->find('ana'));
        $this->assertNull($repository->authenticate('ana', 'secret'));
    }

    #[Test]
    public function aFileThatCanNotBeReadIsAnErrorOfTheConfiguration(): void
    {
        $this->file->remove();

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The htpasswd file "' . $this->file->path() . '" can not be read.');

        $this->repository()->find('ana');
    }

    #[Test]
    public function aDirectoryIsNotAFile(): void
    {
        $this->expectException(ConfigurationException::class);

        (new HtpasswdUserRepository(Stack::htpasswdConfiguration(['htpasswd_path' => sys_get_temp_dir()])))
            ->authenticate('ana', 'secret');
    }

    #[Test]
    public function theUserIsMadeByTheFactory(): void
    {
        $repository = new HtpasswdUserRepository($this->file->config(), new CustomUserFactory());

        $this->assertInstanceOf(CustomUser::class, $repository->authenticate('ana', 'secret'));
        $this->assertInstanceOf(CustomUser::class, $repository->find('ana'));
    }

    #[Test]
    public function theConfigurationNeedsTheFile(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('The path of the htpasswd file is not configured: set AUTH_HTPASSWD_PATH.');

        (Stack::htpasswdConfiguration([]))->validate();
    }

    #[Test]
    public function theConfigurationGivesThePath(): void
    {
        $config = Stack::htpasswdConfiguration([
            'htpasswd_path' => '%kernel.project_dir%/etc/.htpasswd',
            'project_dir' => '/app',
        ]);

        $config->validate();
        $this->assertSame('/app/etc/.htpasswd', $config->getHtpasswdPath());
    }

    #[Test]
    public function theRolesAreTheGroupsOfTheGroupFileThatHaveTheUser(): void
    {
        $this->file->groups(['admin' => ['ana', 'beto'], 'editor' => ['ana']]);
        $repository = $this->repository();

        $this->assertSame(['admin', 'editor'], $repository->authenticate('ana', 'secret')?->getRoles());
        $this->assertSame(['admin'], $repository->authenticate('beto', 'other')?->getRoles());
        // A session finds the user again with the same roles.
        $this->assertSame(['admin', 'editor'], $repository->find('ana')?->getRoles());
    }

    #[Test]
    public function aUserThatIsInNoGroupHasNoRoles(): void
    {
        $this->file->groups(['admin' => ['beto']]);

        $this->assertSame([], $this->repository()->authenticate('ana', 'secret')?->getRoles());
    }

    #[Test]
    public function theGroupFileIgnoresCommentsBlankLinesAndWhatIsNotAGroup(): void
    {
        $this->file->groups([]);
        $this->file->appendGroup('# who can do what');
        $this->file->appendGroup('');
        $this->file->appendGroup('not a group');
        $this->file->appendGroup(": ana");
        $this->file->appendGroup("admin:   ana \t beto  ");
        $this->file->appendGroup('admin: ana');

        $repository = $this->repository();

        $this->assertSame(['admin'], $repository->find('ana')?->getRoles());
        $this->assertSame(['admin'], $repository->find('beto')?->getRoles());
    }

    #[Test]
    public function aUserThatIsInAGroupAndNotInTheHtpasswdIsNotAUser(): void
    {
        $this->file->groups(['admin' => ['ana', 'ghost']]);
        $repository = $this->repository();

        $this->assertNull($repository->find('ghost'));
        $this->assertNull($repository->authenticate('ghost', 'secret'));
    }

    #[Test]
    public function aChangeInTheGroupFileIsSeenByTheNextRequest(): void
    {
        $this->file->groups(['admin' => ['ana']]);
        $repository = $this->repository();
        $before = $repository->find('ana');

        $this->file->groups(['editor' => ['ana']]);
        $after = $repository->find('ana');

        $this->assertSame(['admin'], $before?->getRoles());
        $this->assertSame(['editor'], $after?->getRoles());
    }

    #[Test]
    public function aGroupFileThatCanNotBeReadIsAConfigurationError(): void
    {
        $repository = new HtpasswdUserRepository(Stack::htpasswdConfiguration([
            'htpasswd_path' => $this->file->path(),
            'group_path' => $this->file->path() . '.missing',
        ]));

        $this->expectException(ConfigurationException::class);

        $repository->authenticate('ana', 'secret');
    }

    #[Test]
    public function theGroupPathCanUseTheProjectDirectory(): void
    {
        $config = Stack::htpasswdConfiguration([
            'htpasswd_path' => '%kernel.project_dir%/.htpasswd',
            'group_path' => '%kernel.project_dir%/.htgroup',
            'project_dir' => '/app',
        ]);

        $this->assertSame('/app/.htpasswd', $config->getHtpasswdPath());
        $this->assertSame('/app/.htgroup', $config->getGroupPath());
    }
}
