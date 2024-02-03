<?php declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Monolog\Handler\StreamHandler;
use RedactSensitive\HashSensitiveProcessor;

$sensitive_keys = ['you_know_nothing' => 0];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new \Monolog\Logger('Example', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$logger->info('Completely hidden', ['you_know_nothing' => 'John Snow']);