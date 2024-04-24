<?php

namespace GlobyApp\HashSensitive;

use UnexpectedValueException;

/**
 * Class to manage scrubbing the keys from an array
 *
 * @author sjustein
 */
class Hasher
{
    private ?int $lengthLimit;
    private string $algorithm;
    private bool $exclusiveSubtree;

    public function __construct(string $algorithm = 'sha256', ?int $lengthLimit = null, bool $exclusiveSubtree = true)
    {
        $this->algorithm = $algorithm;
        $this->lengthLimit = $lengthLimit;
        $this->exclusiveSubtree = $exclusiveSubtree;
    }

    /**
     * Function to hash sensitive keys in an input array
     *
     * @param array $inputArray    The array to hash values in
     * @param array $sensitiveKeys The keys to hash
     *
     * @return array The input array with sensitive keys hashed
     */
    public function scrubKeys(array $inputArray, array $sensitiveKeys): array
    {
        return $this->traverseInputArray($inputArray, $sensitiveKeys);
    }

    /**
     * Function to hash the input value, using the specified hashing algorithm and length limit
     *
     * @param string $value The value to hash
     *
     * @return string|null The hashed value, or null, if the input string was empty
     */
    protected function hash(string $value): ?string
    {
        if (strlen($value) === 0) {
            return null;
        }

        // Cut the input to the length limit specified
        $cutInput = substr($value, 0, $this->lengthLimit);

        if (strlen($cutInput) === 0) {
            return null;
        }

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
    protected function traverse(string $key, array|object $value, array $sensitiveKeys): array|object
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
    protected function traverseInputArray(array $inputArray, array $sensitiveKeys): array
    {
        foreach ($inputArray as $key => $value) {
            if ($value === null) {
                // Nothing to hash or process
                continue;
            }

            // If the value is not an array or an object, hash it if it is a sensitive key
            if (is_scalar($value)) {
                if (in_array($key, $sensitiveKeys) || array_key_exists($key, $sensitiveKeys)) {
                    $inputArray[$key] = $this->hash(print_r($value, true));
                }

                continue;
            }

            // The value is either an array or an object, let traverse handle the specifics
            if (in_array($key, $sensitiveKeys) || array_key_exists($key, $sensitiveKeys)) {
                // If the sensitivekeys are not a subtree, hash the entire subtree
                if (!array_key_exists($key, $sensitiveKeys)) {
                    $inputArray[$key] = $this->hash(print_r($value, true));

                    // Continue to the next value, as there is no subtree or sub-object to traverse
                    continue;
                }

                $inputArray[$key] = $this->traverse($key, $value, $sensitiveKeys[$key]);

                // ExclusiveSubtree turned off means that sub keys should be checked according to ALL keys, not just
                // the keys in their sensitive keys subtree
                if (!$this->exclusiveSubtree) {
                    $inputArray[$key] = $this->traverse($key, $inputArray[$key], $sensitiveKeys);
                }
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
    protected function traverseObject(object $object, array $sensitiveKeys): object
    {
        foreach (get_object_vars($object) as $key => $value) {
            // If the value is not an array or an object, hash it if it is a sensitive key
            if (is_scalar($value)) {
                if (in_array($key, $sensitiveKeys) || array_key_exists($key, $sensitiveKeys)) {
                    $object->{$key} = $this->hash(print_r($value, true));
                }

                continue;
            }

            // The value is either an array or an object, let traverse handle the specifics
            if (in_array($key, $sensitiveKeys) || array_key_exists($key, $sensitiveKeys)) {
                // If the sensitivekeys are not a subtree, hash the entire sub-object
                if (!array_key_exists($key, $sensitiveKeys)) {
                    $object->{$key} = $this->hash(print_r($value, true));

                    // Continue to the next value, as there is no subtree or sub-object to traverse
                    continue;
                }

                $object->{$key} = $this->traverse($key, $value, $sensitiveKeys[$key]);

                if (!$this->exclusiveSubtree) {
                    $object->{$key} = $this->traverse($key, $object->{$key}, $sensitiveKeys);
                }
            } else {
                $object->{$key} = $this->traverse($key, $value, $sensitiveKeys);
            }
        }

        return $object;
    }
}