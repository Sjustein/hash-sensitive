<?php

declare(strict_types=1);

namespace HashSensitiveTests;

use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use Monolog\LogRecord;
use GlobyApp\HashSensitive\HashSensitiveProcessor;

it('plays nice with monolog', function (): void {
    $handler = new TestHandler();
    $processor = new HashSensitiveProcessor(['test_key']);

    $logger = new Logger('Test', [$handler], [$processor]);
    $logger->info('Testing', ['test_key' => 'test_value']);

    expect($handler->hasRecordThatPasses(function (LogRecord $record): bool {
        return $record->context['test_key'] === '4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006';
    }, Level::Info))->toBeTrue();
});

