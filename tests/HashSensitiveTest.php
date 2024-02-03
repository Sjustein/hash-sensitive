<?php

declare(strict_types=1);

namespace HashSensitiveTests;

use HashSensitive\HashSensitiveProcessor;
use TypeError;

it('redacts records contexts', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => 'foobar']);
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('truncates masked characters', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys, lengthLimit: 5);

    $record = $this->getRecord(context: ['test' => 'foobar']);
    // Only `fooba` should be hashed, the first 5 characters of `foobar`
    expect($processor($record)->context)->toBe(['test' => '41cbe1a87981490351ccad5346d96da0ac10678670b31fc0ab209aed1b5bc515']);
});

it('doesn\'t truncate more than the string length', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys, lengthLimit: 10);

    $record = $this->getRecord(context: ['test' => 'foobar']);
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('doesn\'t truncate when length limit is 0', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys, lengthLimit: 0);

    $record = $this->getRecord(context: ['test' => 'foobar']);
    expect($processor($record)->context)->toBe(['test' => null]);
});

it('doesn\'t truncate when length limit is not set', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => 'foobar']);
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});


it('redacts nested arrays', function (): void {
    $sensitive_keys = ['test' => ['nested']];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => ['nested' => 'foobar']]);
    expect($processor($record)->context)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']]);
});

it('keeps non redacted nested arrays intact', function (): void {
    $sensitive_keys = ['test' => ['nested']];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => ['nested' => 'foobar', 'no_hash' => 'foobar']]);
    expect($processor($record)->context)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', 'no_hash' => 'foobar']]);
});

it('redacts inside nested arrays', function (): void {
    $sensitive_keys = ['nested'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => ['nested' => 'foobar']]);
    expect($processor($record)->context)->toBe(['test' => ['nested' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']]);
});

it('redacts nested objects', function (): void {
    $nested = new \stdClass();
    $nested->value = 'foobar';
    $nested->nested = ['value' => 'bazqux'];

    $sensitive_keys = ['test' => ['nested' => ['value', 'nested' => ['value']]]];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => ['nested' => $nested]]);

    expect($processor($record)->context)->toBe(['test' => ['nested' => $nested]])
        ->and($nested->value)->toBe('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')
        ->and($nested->nested['value'])->toBe('972c5e1203896784a7cf9dd60acd443a1065e19ad5f92e59a9180c185f065c04');
});

it('keeps non redacted nested objects intact', function (): void {
    $nested = new \stdClass();
    $nested->value = 'foobar';
    $nested->nested = ['value' => 'bazqux', 'no_hash' => 'foobar'];

    $sensitive_keys = ['test' => ['nested' => ['value', 'nested' => ['value']]]];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => ['nested' => $nested]]);

    expect($processor($record)->context)->toBe(['test' => ['nested' => $nested]])
        ->and($nested->nested['no_hash'])->toBe('foobar');
});

it('redacts inside nested objects', function (): void {
    $nested = new \stdClass();
    $nested->value = 'foobar';
    $nested->nested = ['value' => 'bazqux'];

    $sensitive_keys = ['nested' => ['value']];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => ['nested' => $nested]]);

    expect($processor($record)->context)->toBe(['test' => ['nested' => $nested]])
        ->and($nested->value)->toBe('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')
        ->and($nested->nested['value'])->toBe('972c5e1203896784a7cf9dd60acd443a1065e19ad5f92e59a9180c185f065c04');
});

it('preserves empty values', function (): void {
    $sensitive_keys = ['test', 'optionalKey'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => 'foobar', 'optionalKey' => '']);
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', 'optionalKey' => null]);
});

it('throws when finds an un-traversable value', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => fopen(__FILE__, 'rb')]);
    $processor($record);
})->throws(TypeError::class, 'Argument #2 ($value) must be of type object|array, resource given');
