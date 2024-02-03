# Hash Sensitive [![CI](https://github.com/Sjustein/hash-sensitive/actions/workflows/ci.yml/badge.svg)](https://github.com/Sjustein/hash-sensitive/actions/workflows/ci.yml)

🙈 A Monolog processor that protects sensitive data from miss logging. Forked from: [redact-sensitive](https://github.com/leocavalcante/redact-sensitive) by [Leo Cavalcante](https://github.com/leocavalcante)

Avoids logging something like `{"api_key":"mysupersecretapikey"}` by substituting the value by a hashed version of the value:
```text
Readme.INFO: Hello, World! {"api_key":"TODO"} []
```

## Install
```shell
TODO
```

## Usage

### 1. Prepare your sensitive keys

It is an array of key names, for example:
```php
$sensitive_keys = ['api_key'];
```
Will hash the value of the `api_key`.

### 2. Create a Processor using the keys

You can now create a new Processor with the given keys:

```php
use HashSensitive\HashSensitiveProcessor;

$sensitive_keys = ['api_key'];

$processor = new HashSensitiveProcessor($sensitive_keys);
```

### 3. Set the Processor to a Monolog\Logger

```php
use HashSensitive\HashSensitiveProcessor;

$sensitive_keys = ['api_key'];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new \Monolog\Logger('Readme');
$logger->pushProcessor($processor);
```

## Examples

```php
use Monolog\Handler\StreamHandler;
use HashSensitive\HashSensitiveProcessor;

$sensitive_keys = ['api_key' => 4];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new \Monolog\Logger('Readme', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$logger->info('Hello, World!', ['api_key' => 'mysupersecretapikey']);
```
```text
Readme.INFO: Hello, World! {"api_key":"TODO"} []
```

### Custom format
If you're looking for formating the output with a user defined string, this isn't the right project.
You might want to look into [redact-sensitive](https://github.com/leocavalcante/redact-sensitive).

### Length limit

Use `lengthLimit` to truncate redacted sensitive information, such as lengthy tokens. Truncation always happens before hashing.

```php
use Monolog\Handler\StreamHandler;
use HashSensitive\HashSensitiveProcessor;

$sensitive_keys = ['access_token'];

$processor = new HashSensitiveProcessor($sensitive_keys, lengthLimit: 5);

$logger = new \Monolog\Logger('Example', [new StreamHandler(STDOUT)]);
$logger->pushProcessor($processor);

$logger->info('Truncated secret', ['access_token' => 'Very long JWT ...']);
$logger->info('Truncated secret', ['access_token' => 'Very long token ...']);
```
```text
Example.INFO: Truncated secret {"access_token":"TODO"} []
Example.INFO: Truncated secret {"access_token":"TODO"} []
```

### Nested values

It should work with nested objects and arrays as well.

```php
use Monolog\Handler\StreamHandler;
use HashSensitive\HashSensitiveProcessor;

$sensitive_keys = [
    'nested' => [
        'arr' => [
            'value',
            'or_obj' => ['secret'],
        ],
    ]
];

$processor = new HashSensitiveProcessor($sensitive_keys);

$logger = new \Monolog\Logger('Example', [new StreamHandler(STDOUT)]);
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
```
```text
Example.INFO: Nested {"nested":{"arr":{"value":"TODO","or_obj":{"stdClass":{"secret":"TODO"}}}}} []
```

## Thanks
Feel free to open any issues or PRs.

---
MIT &copy; 2024
