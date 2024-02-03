<?php

declare(strict_types=1);

namespace HashSensitiveTests;

use Monolog\DateTimeImmutable;
use Monolog\Level;
use Monolog\Logger;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Stringable;

abstract class TestCase extends BaseTestCase
{
    /**
     * @phpstan-param value-of<Level::VALUES>|value-of<Level::NAMES>|Level|LogLevel::* $level
     */
    protected function getRecord(int|string|Level $level = Level::Warning, string|Stringable $message = 'test', array $context = [], string $channel = 'test', \DateTimeImmutable $datetime = new DateTimeImmutable(true), array $extra = []): LogRecord
    {
        return new LogRecord(
            datetime: $datetime,
            channel: $channel,
            level: Logger::toMonologLevel($level),
            message: (string) $message,
            context: $context,
            extra: $extra,
        );
    }
}
