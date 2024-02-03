<?php declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Monolog\Handler\StreamHandler;
use RedactSensitive\HashSensitiveProcessor;

$sensitive_keys = ['api_key' => 4];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new \Monolog\Logger('Readme', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$logger->info('Hello, World!', ['api_key' => 'mysupersecretapikey']);