<?php

declare(strict_types=1);

namespace HashSensitive;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;
use UnexpectedValueException;

/**
 * The processor to be added to your Monolog instance.
 * @package HashSensitive
 */
class HashSensitiveProcessor implements ProcessorInterface
{
    private array $sensitiveKeys;
    private ?int $lengthLimit;

    /**
     * Creates a new HashSensitiveProcessor instance.
     *
     * @param array $sensitiveKeys Keys that should trigger the redaction.
     * @param int|null $lengthLimit Max length after redaction.
     */
    public function __construct(array $sensitiveKeys, string $algorithm = 'sha256', ?int $lengthLimit = null)
    {
        $this->sensitiveKeys = $sensitiveKeys;
        $this->lengthLimit = $lengthLimit;
    }


    public function __invoke(LogRecord $record): LogRecord
    {
        $redactedContext = $this->traverseInputArray($record->context, $this->sensitiveKeys);
        return $record->with(context: $redactedContext);
    }

    private function hash(string $value): ?string
    {
        if (strlen($value) === 0) {
            return null;
        }

        $hiddenLength = $valueLength - abs($length);
        $hidden = str_repeat($this->replacement, $hiddenLength);
        $placeholder = sprintf($this->template, $hidden);

        $result = substr_replace($value, $placeholder, max(0, $length), $hiddenLength);

        return $length > 0
            ? substr($result, 0, $this->lengthLimit)
            : substr($result, -$this->lengthLimit);
    }

    /**
     * @param array|object $value
     * @param array|int $keys
     * @return array|object
     */
    private function traverse(string $key, $value, $keys)
    {
        if (is_array($value)) {
            return $this->traverseArr($value, $keys);
        }

        if (is_object($value)) {
            return $this->traverseObj($value, $keys);
        }

        throw new UnexpectedValueException("Don't know how to traverse value at key $key");
    }

    private function traverseInputArray(array $inputArray, array $sensitiveKeys): array
    {
        foreach ($inputArray as $key => $value) {
            if (is_scalar($value)) {
                if (array_key_exists($key, $sensitiveKeys)) {
                    $inputArray[$key] = $this->hash((string) $value);
                }
                continue;
            } else {
                if (array_key_exists($key, $sensitiveKeys)) {
                    $inputArray[$key] = $this->traverse($key, $value, $sensitiveKeys[$key]);
                } else {
                    $inputArray[$key] = $this->traverse($key, $value, $sensitiveKeys);
                }
            }
        }

        return $inputArray;
    }

    private function traverseObj(object $obj, array $keys): object
    {
        foreach (get_object_vars($obj) as $key => $value) {
            if (is_scalar($value)) {
                if (array_key_exists($key, $keys)) {
                    $obj->{$key} = $this->redact((string) $value, $keys[$key]);
                }
                continue;
            } else {
                if (array_key_exists($key, $keys)) {
                    $obj->{$key} = $this->traverse($key, $value, $keys[$key]);
                } else {
                    $obj->{$key} = $this->traverse($key, $value, $keys);
                }
            }
        }

        return $obj;
    }
}
