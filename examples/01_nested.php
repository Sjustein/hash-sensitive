<?php declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use HashSensitive\HashSensitiveProcessor;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

$sensitive_keys = [
    'nested' => [
        'arr' => [
            'value',
            'or_obj' => ['secret'],
        ],
    ],
];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new Logger('Example', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$nested_obj = new stdClass();
$nested_obj->secret = 'donttellanyone';

$logger->info('Nested', [
    'nested' => [
        'arr' => [
            'value' => 'abcdfg',
            'or_obj' => $nested_obj,
        ],
    ],
]);