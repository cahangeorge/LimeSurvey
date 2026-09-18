<?php

declare(strict_types=1);

namespace Omnestack\LimeSurvey\Resend;

use InvalidArgumentException;
use JsonException;
use RuntimeException;
use Throwable;

final class ResendClient
{
    private const ENDPOINT = 'https://api.resend.com/emails';

    /** @var callable(string, string, array<string, string>, string, int, int): array{status: int, body: string} */
    private $httpClient;

    public function __construct(
        private readonly string $apiKey,
        ?callable $httpClient = null,
        private readonly int $connectTimeoutSeconds = 5,
        private readonly int $timeoutSeconds = 15
    ) {
        if ($connectTimeoutSeconds <= 0 || $timeoutSeconds <= 0 || $connectTimeoutSeconds > $timeoutSeconds) {
            throw new InvalidArgumentException('Resend HTTP timeouts must be positive and ordered.');
        }

        $this->httpClient = $httpClient ?? $this->curlRequest(...);
    }

    /**
     * @param array<string, mixed> $message
     */
    public function send(array $message): string
    {
        if (trim($this->apiKey) === '') {
            throw new RuntimeException('RESEND_API_KEY is not configured.');
        }

        if (!empty($message['attachments'])) {
            throw new RuntimeException('Email attachments are not supported by the ResendEmail plugin.');
        }

        $payload = $this->buildPayload($message);

        try {
            $response = ($this->httpClient)(
                'POST',
                self::ENDPOINT,
                [
                    'Authorization' => 'Bearer ' . $this->apiKey,
                    'Content-Type' => 'application/json',
                ],
                json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                $this->connectTimeoutSeconds,
                $this->timeoutSeconds
            );
        } catch (JsonException $exception) {
            throw new RuntimeException('Resend message payload could not be encoded.');
        } catch (Throwable $exception) {
            throw new RuntimeException('Resend transport request failed.');
        }

        $status = (int) ($response['status'] ?? 0);
        if ($status < 200 || $status >= 300) {
            throw new RuntimeException(sprintf('Resend API request failed with HTTP %d.', $status));
        }

        try {
            $decoded = json_decode((string) ($response['body'] ?? ''), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Resend API returned an invalid success response.');
        }

        $id = is_array($decoded) ? ($decoded['id'] ?? null) : null;
        if (!is_string($id) || trim($id) === '') {
            throw new RuntimeException('Resend API returned no message identifier.');
        }

        return $id;
    }

    /**
     * @param array<string, mixed> $message
     * @return array<string, mixed>
     */
    private function buildPayload(array $message): array
    {
        $subject = trim((string) ($message['subject'] ?? ''));
        if ($subject === '') {
            throw new InvalidArgumentException('Email subject is required.');
        }

        $payload = [
            'from' => $this->formatAddress($message['from'] ?? null),
            'to' => $this->formatAddressList($message['to'] ?? []),
            'subject' => $subject,
        ];

        if ($payload['to'] === []) {
            throw new InvalidArgumentException('At least one email recipient is required.');
        }

        foreach (['cc', 'bcc', 'reply_to'] as $field) {
            $addresses = $this->formatAddressList($message[$field] ?? []);
            if ($addresses !== []) {
                $payload[$field] = $addresses;
            }
        }

        $html = isset($message['html']) ? trim((string) $message['html']) : '';
        $text = isset($message['text']) ? trim((string) $message['text']) : '';
        if ($html === '' && $text === '') {
            throw new InvalidArgumentException('Email HTML or text content is required.');
        }
        if ($html !== '') {
            $payload['html'] = $html;
        }
        if ($text !== '') {
            $payload['text'] = $text;
        }

        return $payload;
    }

    /** @return list<string> */
    private function formatAddressList(mixed $addresses): array
    {
        if (!is_array($addresses)) {
            $addresses = [$addresses];
        }

        $formatted = [];
        foreach ($addresses as $address) {
            $formatted[] = $this->formatAddress($address);
        }

        return $formatted;
    }

    private function formatAddress(mixed $address): string
    {
        $email = '';
        $name = '';

        if (is_string($address)) {
            if (preg_match('/^\s*(.*?)\s*<([^<>]+)>\s*$/', $address, $matches) === 1) {
                $name = $matches[1];
                $email = $matches[2];
            } else {
                $email = $address;
            }
        } elseif (is_array($address)) {
            if (array_key_exists('email', $address)) {
                $email = (string) $address['email'];
                $name = (string) ($address['name'] ?? '');
            } else {
                $email = (string) ($address[0] ?? '');
                $name = (string) ($address[1] ?? '');
            }
        }

        $email = trim($email);
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || preg_match('/[\r\n]/', $email)) {
            throw new InvalidArgumentException('A valid email address is required.');
        }

        $name = trim((string) preg_replace('/[\r\n<>]+/', ' ', $name));
        return $name === '' ? $email : sprintf('%s <%s>', $name, $email);
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string}
     */
    private function curlRequest(
        string $method,
        string $url,
        array $headers,
        string $body,
        int $connectTimeoutSeconds,
        int $timeoutSeconds
    ): array {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The PHP cURL extension is required.');
        }

        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Could not initialize the HTTP transport.');
        }

        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        try {
            curl_setopt_array($handle, [
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => $headerLines,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => $connectTimeoutSeconds,
                CURLOPT_TIMEOUT => $timeoutSeconds,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            ]);
            $responseBody = curl_exec($handle);
            if ($responseBody === false) {
                throw new RuntimeException('The HTTPS request failed.');
            }

            return [
                'status' => (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE),
                'body' => (string) $responseBody,
            ];
        } finally {
            curl_close($handle);
        }
    }
}
