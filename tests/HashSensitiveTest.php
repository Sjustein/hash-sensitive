<?php

declare(strict_types=1);

namespace HashSensitiveTests;

use GlobyApp\HashSensitive\HashSensitiveProcessor;
use TypeError;

it('redacts records contexts', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => 'foobar']);
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2']);
});

it('works without sensitive key subtrees', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => ['foobar' => 'test']]);
    expect($processor($record)->context)->toBe(['test' => 'c413de2c94a3a668b82ae2207da4b6961eeeccaff97623e2143d978610cb4746']);
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

it('works without sensitive key subobjects', function (): void {
    $sensitive_keys = ['test'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $nested = new \stdClass();
    $nested->foobar = "test";

    $obj = new \stdClass();
    $obj->test = $nested;

    $record = $this->getRecord(context: ['obj' => $obj]);
    expect($processor($record)->context)->toBe(['obj' => $obj])
        ->and($obj->test)->toBe('914dba76d2c953789b8ec73425b85bea1c8298815dd0afc1e4fc6c2d8be69648');
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

// ExclusiveSubtree stories
it('it hashes all instances with exclusiveSubtree false in arrays', function (): void {
    $sensitive_keys = ['test', 'test_subkey' => ['to_hash']];
    $processor = new HashSensitiveProcessor($sensitive_keys, exclusiveSubtree: false);

    $record = $this->getRecord(context: ['test_key' => 'test_value', 'test_subkey' => ['to_hash' => 'test_value', 'test' => 'test']]);
    expect($processor($record)->context)->toBe(['test_key' => 'test_value', 'test_subkey' => ['to_hash' => '4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006', 'test' => '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']]);
});

it('it hashes all instances with exclusiveSubtree true in arrays', function (): void {
    $sensitive_keys = ['test', 'test_subkey' => ['to_hash']];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test_key' => 'test_value', 'test_subkey' => ['to_hash' => 'test_value', 'test' => 'test']]);
    expect($processor($record)->context)->toBe(['test_key' => 'test_value', 'test_subkey' => ['to_hash' => '4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006', 'test' => 'test']]);
});

it('it hashes all instances with exclusiveSubtree false in nested objects', function (): void {
    $nested = new \stdClass();
    $nested->to_hash = 'test_value';
    $nested->test = 'test';

    $sensitive_keys = ['test', 'test_subkey' => ['to_hash']];
    $processor = new HashSensitiveProcessor($sensitive_keys, exclusiveSubtree: false);

    $record = $this->getRecord(context: ['test_key' => 'test_value', 'test_subkey' => $nested]);
    expect($processor($record)->context)->toBe(['test_key' => 'test_value', 'test_subkey' => $nested])
        ->and($nested->to_hash)->toBe('4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006')
        ->and($nested->test)->toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
});

it('it hashes all instances with exclusiveSubtree true in nested objects', function (): void {
    $nested = new \stdClass();
    $nested->to_hash = 'test_value';
    $nested->test = 'test';

    $sensitive_keys = ['test', 'test_subkey' => ['to_hash']];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test_key' => 'test_value', 'test_subkey' => $nested]);
    expect($processor($record)->context)->toBe(['test_key' => 'test_value', 'test_subkey' => $nested])
        ->and($nested->to_hash)->toBe('4f7f6a4ae46676d9751fdccdf15ae1e6a200ed0de5653e06390148928c642006')
        ->and($nested->test)->toBe('test');
});

it('preserves empty values', function (): void {
    $sensitive_keys = ['test', 'optionalKey'];
    $processor = new HashSensitiveProcessor($sensitive_keys);

    $record = $this->getRecord(context: ['test' => 'foobar', 'optionalKey' => '']);
    expect($processor($record)->context)->toBe(['test' => 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', 'optionalKey' => null]);
});