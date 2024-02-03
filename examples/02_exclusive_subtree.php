<?php declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use HashSensitive\HashSensitiveProcessor;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

$sensitive_keys = [
    'test',
    'test_subkey' => ['to_hash'],
];

$processor = new HashSensitiveProcessor($sensitive_keys, exclusiveSubtree: false);
$processorExclusive = new HashSensitiveProcessor($sensitive_keys, exclusiveSubtree: true);

$logger = new Logger('Example', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processorExclusive);

$logger->info('Exclusive subtree', [
    'test_key' => 'test_value',
    'test_subkey' => [
        'to_hash' => 'test_value',
        'test' => 'test',
    ],
]);

$logger->pushProcessor($processor);
$logger->info('Non exclusive subtree', [
    'test_key' => 'test_value',
    'test_subkey' => [
        'to_hash' => 'test_value',
        'test' => 'test',
    ],
]);