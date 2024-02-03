<?php declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Monolog\Handler\StreamHandler;
use HashSensitive\HashSensitiveProcessor;
use Monolog\Logger;

$sensitive_keys = ['api_key'];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new Logger('Readme', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$logger->info('Hello, World!', ['api_key' => 'mysupersecretapikey']);