<?php

declare(strict_types=1);

namespace GlobyApp\HashSensitive;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;
use UnexpectedValueException;

/**
 * The processor to be added to your Monolog instance.
 * @package GlobyApp\HashSensitive
 */
class HashSensitiveProcessor extends Hasher implements ProcessorInterface
{
    private array $sensitiveKeys;

    /**
     * Creates a new HashSensitiveProcessor instance.
     *
     * @param array $sensitiveKeys Keys that should trigger the redaction.
     * @param int|null $lengthLimit Max length after redaction.
     */
    public function __construct(array $sensitiveKeys, string $algorithm = 'sha256', ?int $lengthLimit = null, bool $exclusiveSubtree = true)
    {
        $this->sensitiveKeys = $sensitiveKeys;

        parent::__construct($algorithm, $lengthLimit, $exclusiveSubtree);
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
}
