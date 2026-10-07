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

use GuzzleHttp\Client;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A PSR-18 client (Guzzle) that keeps the requests that it makes, to know how
 * many times a token was verified against the realm, and that can answer the
 * first requests with a body that is given, as the realm would before it rotated
 * its keys.
 */
final class RecordingHttpClient implements ClientInterface
{
    /**
     * @var list<RequestInterface>
     */
    public array $requests = [];

    private readonly Client $http;

    /**
     * @param list<string> $answers The bodies (JSON) of the first requests; the
     * ones after them are answered by the real server.
     */
    public function __construct(private array $answers = [])
    {
        $this->http = new Client();
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        if ($this->answers !== []) {
            return new \GuzzleHttp\Psr7\Response(
                200,
                ['Content-Type' => 'application/json'],
                array_shift($this->answers)
            );
        }

        return $this->http->sendRequest($request);
    }
}
