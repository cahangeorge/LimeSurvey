<?php

declare(strict_types=1);

namespace LimeSurvey\Datavalueobjects {
    final class EmailPluginInfo
    {
        public function __construct(...$arguments)
        {
        }
    }
}

namespace LimeSurvey\PluginManager {
    use LimeSurvey\Datavalueobjects\EmailPluginInfo;

    abstract class EmailPluginBase
    {
        protected object $event;

        public function setEventForTest(object $event): void
        {
            $this->event = $event;
        }

        protected function getEvent(): object
        {
            return $this->event;
        }

        protected function getEmailPluginInfo(): EmailPluginInfo
        {
            return new EmailPluginInfo();
        }

        protected function subscribe(string $event): void
        {
        }

        abstract protected function getDisplayName();
    }
}

namespace Tests {
    use Omnestack\LimeSurvey\Resend\ResendClient;
    use PHPUnit\Framework\TestCase;
    use ReflectionProperty;
    use RuntimeException;
    use Tests\Fakes\FakeHttpClient;

    final class ResendEmailPluginTest extends TestCase
    {
        private const API_KEY = 'test_resend_key_for_unit_tests_only';

        protected function tearDown(): void
        {
            putenv('RESEND_API_KEY');
            putenv('RESEND_FROM_EMAIL');
            putenv('RESEND_FROM_NAME');
        }

        public function testMapsHtmlMessageAndAddressesToResendPayload(): void
        {
            $this->requireClientImplementation();
            $http = new FakeHttpClient();
            $client = new ResendClient(self::API_KEY, $http);

            $id = $client->send([
                'from' => ['email' => 'sender@example.com', 'name' => 'Survey Sender'],
                'to' => [
                    ['person@example.com', 'Person One'],
                    ['second@example.com', ''],
                ],
                'cc' => [['copy@example.com', 'Copy']],
                'bcc' => [['audit@example.com', 'Audit']],
                'reply_to' => ['reply@example.com' => ['reply@example.com', 'Reply Desk']],
                'subject' => 'Survey confirmation',
                'html' => '<p>Thank you</p>',
                'text' => 'Thank you',
                'attachments' => [],
            ]);

            self::assertSame('email_test_123', $id);
            $request = $http->lastRequest();
            self::assertSame('POST', $request['method']);
            self::assertSame('https://api.resend.com/emails', $request['url']);
            self::assertSame('Bearer ' . self::API_KEY, $request['headers']['Authorization']);
            self::assertSame('application/json', $request['headers']['Content-Type']);

            $payload = json_decode($request['body'], true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('Survey Sender <sender@example.com>', $payload['from']);
            self::assertSame(['Person One <person@example.com>', 'second@example.com'], $payload['to']);
            self::assertSame(['Copy <copy@example.com>'], $payload['cc']);
            self::assertSame(['Audit <audit@example.com>'], $payload['bcc']);
            self::assertSame(['Reply Desk <reply@example.com>'], $payload['reply_to']);
            self::assertSame('<p>Thank you</p>', $payload['html']);
            self::assertSame('Thank you', $payload['text']);
        }

        public function testMapsPlainTextMessageWithoutHtmlField(): void
        {
            $this->requireClientImplementation();
            $http = new FakeHttpClient();
            $client = new ResendClient(self::API_KEY, $http);

            $client->send($this->plainMessage());

            $payload = json_decode($http->lastRequest()['body'], true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('Plain body', $payload['text']);
            self::assertArrayNotHasKey('html', $payload);
        }

        public function testRejectsMissingApiKeyWithoutNetworkCall(): void
        {
            $this->requireClientImplementation();
            $http = new FakeHttpClient();
            $client = new ResendClient('', $http);

            $this->expectException(RuntimeException::class);
            $this->expectExceptionMessage('RESEND_API_KEY is not configured');

            try {
                $client->send($this->plainMessage());
            } finally {
                self::assertSame([], $http->requests);
            }
        }

        public function testUsesFiniteConnectAndRequestTimeouts(): void
        {
            $this->requireClientImplementation();
            $http = new FakeHttpClient();
            $client = new ResendClient(self::API_KEY, $http, 4, 12);

            $client->send($this->plainMessage());

            $request = $http->lastRequest();
            self::assertSame(4, $request['connectTimeoutSeconds']);
            self::assertSame(12, $request['timeoutSeconds']);
            self::assertGreaterThan(0, $request['connectTimeoutSeconds']);
            self::assertLessThanOrEqual(30, $request['timeoutSeconds']);
        }

        public function testNonSuccessfulResponseDoesNotLeakAuthorization(): void
        {
            $this->requireClientImplementation();
            $http = new FakeHttpClient();
            $http->status = 422;
            $http->body = '{"message":"validation failed"}';
            $client = new ResendClient(self::API_KEY, $http);

            try {
                $client->send($this->plainMessage());
                self::fail('Expected the non-2xx response to fail.');
            } catch (RuntimeException $exception) {
                self::assertStringContainsString('HTTP 422', $exception->getMessage());
                self::assertStringNotContainsString(self::API_KEY, $exception->getMessage());
                self::assertStringNotContainsString('Bearer', $exception->getMessage());
            }
        }

        public function testTransportExceptionDoesNotLeakApiKey(): void
        {
            $this->requireClientImplementation();
            $http = new FakeHttpClient();
            $http->exception = new RuntimeException('transport failed using ' . self::API_KEY);
            $client = new ResendClient(self::API_KEY, $http);

            try {
                $client->send($this->plainMessage());
                self::fail('Expected the transport exception to fail.');
            } catch (RuntimeException $exception) {
                self::assertSame('Resend transport request failed.', $exception->getMessage());
                self::assertStringNotContainsString(self::API_KEY, $exception->getMessage());
            }
        }

        public function testAttachmentsFailClosedBeforeNetworkCall(): void
        {
            $this->requireClientImplementation();
            $http = new FakeHttpClient();
            $client = new ResendClient(self::API_KEY, $http);
            $message = $this->plainMessage();
            $message['attachments'] = [['path' => '/tmp/example.pdf']];

            try {
                $client->send($message);
                self::fail('Expected unsupported attachments to fail closed.');
            } catch (RuntimeException $exception) {
                self::assertStringContainsString('attachments are not supported', strtolower($exception->getMessage()));
                self::assertSame([], $http->requests);
            }
        }

        public function testPluginSignalsAcceptedDeliveryAndMapsMailer(): void
        {
            $plugin = $this->pluginWithClient($client = new StubResendClient('email_test_accepted'));
            $event = new StubPluginEvent(['mailer' => new StubMailer()]);
            $plugin->setEventForTest($event);

            $plugin->beforeEmailDispatch();

            self::assertFalse($event->get('send'));
            self::assertNull($event->get('error'));
            self::assertSame('email_test_accepted', $event->get('message'));
            self::assertSame('Verified Sender <verified@example.com>', $client->message['from']);
            self::assertSame([['person@example.com', 'Person']], $client->message['to']);
            self::assertSame(['reply@example.com' => ['reply@example.com', 'Reply']], $client->message['reply_to']);
            self::assertSame('<p>Body</p>', $client->message['html']);
            self::assertSame('Body', $client->message['text']);
        }

        public function testPluginFailureSignalsErrorWithoutLeakingSecret(): void
        {
            $plugin = $this->pluginWithClient(new StubResendClient(exception: new RuntimeException(self::API_KEY)));
            $event = new StubPluginEvent(['mailer' => new StubMailer()]);
            $plugin->setEventForTest($event);

            $plugin->beforeEmailDispatch();

            self::assertFalse($event->get('send'));
            self::assertSame('Email delivery through Resend failed.', $event->get('error'));
            self::assertStringNotContainsString(self::API_KEY, (string) $event->get('error'));
        }

        /** @return array<string, mixed> */
        private function plainMessage(): array
        {
            return [
                'from' => 'sender@example.com',
                'to' => [['person@example.com', '']],
                'cc' => [],
                'bcc' => [],
                'reply_to' => [],
                'subject' => 'Plain message',
                'text' => 'Plain body',
                'attachments' => [],
            ];
        }

        private function requireClientImplementation(): void
        {
            self::assertTrue(
                class_exists(ResendClient::class),
                'ResendClient implementation is missing; this is the expected Task 6 red state.'
            );
        }

        private function pluginWithClient(StubResendClient $client): object
        {
            $pluginPath = dirname(__DIR__) . '/plugins/ResendEmail/ResendEmail.php';
            self::assertFileExists(
                $pluginPath,
                'ResendEmail plugin implementation is missing; this is the expected Task 6 red state.'
            );
            require_once $pluginPath;
            self::assertTrue(class_exists(\ResendEmail::class));

            putenv(sprintf('%s=%s', 'RESEND_API_KEY', self::API_KEY));
            putenv('RESEND_FROM_EMAIL=verified@example.com');
            putenv('RESEND_FROM_NAME=Verified Sender');

            $plugin = new \ResendEmail();
            $factory = new ReflectionProperty($plugin, 'clientFactory');
            $factory->setValue($plugin, static fn (): StubResendClient => $client);

            return $plugin;
        }
    }

    final class StubPluginEvent
    {
        /** @param array<string, mixed> $values */
        public function __construct(private array $values)
        {
        }

        public function get(string $name, mixed $default = null): mixed
        {
            return $this->values[$name] ?? $default;
        }

        public function set(string $name, mixed $value): void
        {
            $this->values[$name] = $value;
        }

        public function append(string $name, mixed $value): void
        {
            $this->values[$name][] = $value;
        }
    }

    final class StubMailer
    {
        public string $Subject = 'Subject';

        public string $Body = '<p>Body</p>';

        public string $AltBody = 'Body';

        public function getFrom(): string
        {
            return 'Survey Sender <survey@example.com>';
        }

        public function getToAddresses(): array
        {
            return [['person@example.com', 'Person']];
        }

        public function getCcAddresses(): array
        {
            return [];
        }

        public function getBccAddresses(): array
        {
            return [];
        }

        public function getReplyToAddresses(): array
        {
            return ['reply@example.com' => ['reply@example.com', 'Reply']];
        }

        public function getAttachments(): array
        {
            return [];
        }

        public function getIsHtml(): bool
        {
            return true;
        }
    }

    final class StubResendClient
    {
        /** @var array<string, mixed> */
        public array $message = [];

        public function __construct(
            private string $id = '',
            private ?RuntimeException $exception = null
        ) {
        }

        /** @param array<string, mixed> $message */
        public function send(array $message): string
        {
            $this->message = $message;
            if ($this->exception !== null) {
                throw $this->exception;
            }

            return $this->id;
        }
    }
}
