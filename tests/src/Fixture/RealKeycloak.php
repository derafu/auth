<?php

declare(strict_types=1);

/**
 * Derafu: Auth - Authentication and Authorization for PHP applications.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsAuth\Fixture;

use RuntimeException;

/**
 * A real Keycloak, in a container of Docker, with the realm `test`
 * (`fixtures/keycloak/test-realm.json`): a confidential client that requires
 * PKCE and has the redirect URI and the post logout redirect URI of the tests,
 * the roles `admin` and `editor`, and the user `ana` (password `secret`, role
 * `admin`). The user and the credentials are of the realm of the tests: they
 * exist only in this container.
 *
 * What depends on how Keycloak really answers (its tokens, its keys, its
 * logout, its PKCE) is tested against it, and not against a double that would
 * only prove what the double was written to say.
 */
final class RealKeycloak
{
    /**
     * The version of Keycloak of the tests.
     */
    public const IMAGE = 'quay.io/keycloak/keycloak:26.8.0';

    private function __construct(
        private readonly string $container,
        public readonly int $port
    ) {
    }

    /**
     * Starts Keycloak in a free port and waits until the realm answers.
     *
     * @throws RuntimeException If Docker is not available or Keycloak does not
     * start.
     */
    public static function start(): self
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
        if ($socket === false) {
            throw new RuntimeException('No free port: ' . $error);
        }
        $port = (int) substr(strrchr((string) stream_socket_get_name($socket, false), ':'), 1);
        fclose($socket);

        $command = sprintf(
            'docker run -d --rm -p 127.0.0.1:%d:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin '
                . '-e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -v %s:/opt/keycloak/data/import:ro %s start-dev --import-realm 2>&1',
            $port,
            escapeshellarg(dirname(__DIR__, 2) . '/fixtures/keycloak'),
            self::IMAGE
        );
        exec($command, $output, $status);
        if ($status !== 0) {
            throw new RuntimeException("Docker could not start Keycloak:\n" . implode("\n", $output));
        }
        $keycloak = new self(trim((string) end($output)), $port);

        $url = $keycloak->url() . '/realms/test/.well-known/openid-configuration';
        for ($attempt = 0; $attempt < 120; $attempt++) {
            $answer = @file_get_contents($url);
            if ($answer !== false) {
                return $keycloak;
            }
            sleep(1);
        }

        $keycloak->stop();

        throw new RuntimeException('Keycloak did not start in two minutes.');
    }

    /**
     * The URL of Keycloak.
     */
    public function url(): string
    {
        return 'http://127.0.0.1:' . $this->port;
    }

    /**
     * The administrator of this Keycloak.
     */
    public function admin(): KeycloakAdmin
    {
        return new KeycloakAdmin($this->url());
    }

    /**
     * Freezes Keycloak: its port stays open and nothing answers, as a server
     * that does not respond. A request waits until its own timeout.
     */
    public function pause(): void
    {
        exec('docker pause ' . escapeshellarg($this->container) . ' 2>&1');
    }

    /**
     * Gives Keycloak its life back.
     */
    public function unpause(): void
    {
        exec('docker unpause ' . escapeshellarg($this->container) . ' 2>&1');
    }

    /**
     * Stops Keycloak and removes its container.
     */
    public function stop(): void
    {
        exec('docker stop -t 1 ' . escapeshellarg($this->container) . ' 2>&1');
    }
}
