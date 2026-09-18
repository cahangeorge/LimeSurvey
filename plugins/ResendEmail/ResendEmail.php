<?php

declare(strict_types=1);

use LimeSurvey\PluginManager\EmailPluginBase;
use Omnestack\LimeSurvey\Resend\ResendClient;
use Omnestack\LimeSurvey\Resend\UnsupportedAttachmentException;

require_once __DIR__ . '/ResendClient.php';

class ResendEmail extends EmailPluginBase
{
    protected $storage = 'DbStorage';

    protected static $description = 'Sends LimeSurvey email through the Resend HTTPS API.';

    protected static $name = 'ResendEmail';

    public $allowedPublicMethods = [];

    /** @var callable|null Used only to inject a no-network client in unit tests. */
    protected $clientFactory = null;

    public function init(): void
    {
        $this->subscribe('listEmailPlugins');
        $this->subscribe('afterSelectEmailPlugin');
        $this->subscribe('beforeEmailDispatch');
    }

    protected function getDisplayName(): string
    {
        return 'Resend HTTPS API';
    }

    public function listEmailPlugins(): void
    {
        $this->getEvent()->append('plugins', [
            'resend' => $this->getEmailPluginInfo(),
        ]);
    }

    public function afterSelectEmailPlugin(): void
    {
        if ($this->environment('RESEND_API_KEY') === '') {
            $this->getEvent()->set('warning', 'RESEND_API_KEY is not configured for the ResendEmail plugin.');
        }
    }

    public function beforeEmailDispatch(): void
    {
        $event = $this->getEvent();
        $mailer = $event->get('mailer');

        try {
            if (!is_object($mailer)) {
                throw new RuntimeException('LimeMailer is unavailable.');
            }

            $messageId = $this->createClient()->send($this->messageFromMailer($mailer));
            $event->set('send', false);
            $event->set('error', null);
            $event->set('message', $messageId);
        } catch (UnsupportedAttachmentException $exception) {
            if (method_exists($this, 'log')) {
                $this->log('Resend email rejected an unsupported attachment.', CLogger::LEVEL_WARNING);
            }
            $event->set('send', false);
            $event->set('error', $exception->getMessage());
        } catch (\Throwable $exception) {
            if (method_exists($this, 'log')) {
                $this->log('Resend email delivery failed.', CLogger::LEVEL_WARNING);
            }
            $event->set('send', false);
            $event->set('error', 'Email delivery through Resend failed.');
        }
    }

    protected function createClient(): object
    {
        if (is_callable($this->clientFactory)) {
            return ($this->clientFactory)();
        }

        return new ResendClient($this->environment('RESEND_API_KEY'));
    }

    /** @return array<string, mixed> */
    private function messageFromMailer(object $mailer): array
    {
        $configuredFromEmail = $this->environment('RESEND_FROM_EMAIL');
        $configuredFromName = $this->environment('RESEND_FROM_NAME');
        $originalFrom = $mailer->getFrom();
        $from = $configuredFromEmail === ''
            ? $originalFrom
            : ($configuredFromName === ''
                ? $configuredFromEmail
                : sprintf('%s <%s>', $configuredFromName, $configuredFromEmail));

        $replyTo = $mailer->getReplyToAddresses();
        if ($configuredFromEmail !== '' && $replyTo === []) {
            $replyTo = [$originalFrom];
        }

        $isHtml = $mailer->getIsHtml();
        $text = $isHtml
            ? (trim((string) $mailer->AltBody) !== '' ? (string) $mailer->AltBody : trim(strip_tags((string) $mailer->Body)))
            : (string) $mailer->Body;

        return [
            'from' => $from,
            'to' => $mailer->getToAddresses(),
            'cc' => $mailer->getCcAddresses(),
            'bcc' => $mailer->getBccAddresses(),
            'reply_to' => $replyTo,
            'subject' => (string) $mailer->Subject,
            'html' => $isHtml ? (string) $mailer->Body : '',
            'text' => $text,
            'attachments' => $mailer->getAttachments(),
        ];
    }

    private function environment(string $name): string
    {
        $value = getenv($name);
        return $value === false ? '' : trim($value);
    }
}
