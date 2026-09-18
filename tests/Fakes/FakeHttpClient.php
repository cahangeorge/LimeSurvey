<?php

declare(strict_types=1);

namespace Tests\Fakes;

use RuntimeException;
use Throwable;

final class FakeHttpClient
{
    /** @var list<array<string, mixed>> */
    public array $requests = [];

    public int $status = 200;

    public string $body = '{"id":"email_test_123"}';

    public ?Throwable $exception = null;

    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string}
     */
    public function __invoke(
        string $method,
        string $url,
        array $headers,
        string $body,
        int $connectTimeoutSeconds,
        int $timeoutSeconds
    ): array {
        $this->requests[] = [
            'method' => $method,
            'url' => $url,
            'headers' => $headers,
            'body' => $body,
            'connectTimeoutSeconds' => $connectTimeoutSeconds,
            'timeoutSeconds' => $timeoutSeconds,
        ];

        if ($this->exception !== null) {
            throw $this->exception;
        }

        return ['status' => $this->status, 'body' => $this->body];
    }

    public function lastRequest(): array
    {
        if ($this->requests === []) {
            throw new RuntimeException('No HTTP request was captured.');
        }

        return $this->requests[array_key_last($this->requests)];
    }
}
