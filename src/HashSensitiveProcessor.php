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
    private string $algorithm;

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
        $this->algorithm = $algorithm;
    }

    /**
     * Invoke hook into the monolog processor execution.
     *
     * @param LogRecord $record Log record before being processed.
     *
     * @return LogRecord Log record with redacted values hashed.
     */
    public function __invoke(LogRecord $record): LogRecord
    {
        $redactedContext = $this->traverseInputArray($record->context, $this->sensitiveKeys);
        return $record->with(context: $redactedContext);
    }

    /**
     * Function to hash the input value, using the specified hashing algorithm and length limit
     *
     * @param string $value The value to hash
     *
     * @return string|null The hashed value, or null, if the input string was empty
     */
    private function hash(string $value): ?string
    {
        if (strlen($value) === 0) {
            return null;
        }

        // Cut the input to the length limit specified
        $cutInput = substr($value, 0, $this->lengthLimit);
        return hash($this->algorithm, $cutInput);
    }

    /**
     * Function to handle traversing arrays and objects
     *
     * @param string       $key           The key being processed
     * @param array|object $value         The value of the key in the input data
     * @param array        $sensitiveKeys The list of keys to hash
     *
     * @throws UnexpectedValueException if $value was not either an array of an object
     *
     * @return array|object The processed array or object
     */
    private function traverse(string $key, array|object $value, array $sensitiveKeys): array|object
    {
        if (is_array($value)) {
            return $this->traverseInputArray($value, $sensitiveKeys);
        }

        if (is_object($value)) {
            return $this->traverseObject($value, $sensitiveKeys);
        }

        throw new UnexpectedValueException("Don't know how to traverse value at key $key");
    }

    /**
     * Traverse an array and replace all values to be redacted with a hashed version of the value
     *
     * @param array $inputArray    Array to redact values from
     * @param array $sensitiveKeys Keys to redact
     *
     * @return array Input array with redacted values hashed
     */
    private function traverseInputArray(array $inputArray, array $sensitiveKeys): array
    {
        foreach ($inputArray as $key => $value) {
            if ($value === null) {
                // Nothing to hash or process
                continue;
            }

            // If the value is not an array or an object, hash it if it is a sensitive key
            if (is_scalar($value)) {
                if (array_key_exists($key, $sensitiveKeys)) {
                    $inputArray[$key] = $this->hash((string) $value);
                }

                continue;
            }

            // The value is either an array or an object, let traverse handle the specifics
            if (array_key_exists($key, $sensitiveKeys)) {
                $inputArray[$key] = $this->traverse($key, $value, $sensitiveKeys[$key]);
            } else {
                $inputArray[$key] = $this->traverse($key, $value, $sensitiveKeys);
            }
        }

        return $inputArray;
    }

    /**
     * Traverse an object and replace all values to be redacted with a hashed version of the value
     *
     * @param object $object        Object to redact values from
     * @param array  $sensitiveKeys Keys for which to hash the value
     *
     * @return object The object with redacted values hashed
     */
    private function traverseObject(object $object, array $sensitiveKeys): object
    {
        foreach (get_object_vars($object) as $key => $value) {
            // If the value is not an array or an object, hash it if it is a sensitive key
            if (is_scalar($value)) {
                if (array_key_exists($key, $sensitiveKeys)) {
                    $object->{$key} = $this->hash((string) $value);
                }

                continue;
            }

            // The value is either an array or an object, let traverse handle the specifics
            if (array_key_exists($key, $sensitiveKeys)) {
                $object->{$key} = $this->traverse($key, $value, $sensitiveKeys[$key]);
            } else {
                $object->{$key} = $this->traverse($key, $value, $sensitiveKeys);
            }
        }

        return $object;
    }
}
