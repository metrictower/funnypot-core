<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Acceptance;

use InvalidArgumentException;

final class EvidenceFiles
{
    /** @return array<int,mixed> */
    public static function jsonLines(string $path): array
    {
        $bytes = @file_get_contents($path);
        if (!is_string($bytes)) {
            return [['malformed_jsonl' => true]];
        }
        $result = [];
        foreach (preg_split('/\r?\n/', trim($bytes)) as $line) {
            if ($line === '') {
                continue;
            }
            $decoded = json_decode($line, true);
            if (!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
                return [['malformed_jsonl' => true]];
            }
            $result[] = $decoded;
        }

        return $result;
    }

    /** Decode the concatenated JSON objects emitted by Nuclei's pinned trace writer. @return array<int,mixed> */
    public static function jsonSequence(string $path): array
    {
        $bytes = @file_get_contents($path);
        if (!is_string($bytes) || $bytes === '') {
            return [];
        }
        $records = [];
        $length = strlen($bytes);
        $start = null;
        $depth = 0;
        $quoted = false;
        $escaped = false;
        for ($offset = 0; $offset < $length; $offset++) {
            $char = $bytes[$offset];
            if ($start === null) {
                if (ctype_space($char)) {
                    continue;
                }
                if ($char !== '{') {
                    return [['malformed_trace' => true]];
                }
                $start = $offset;
                $depth = 1;
                continue;
            }
            if ($quoted) {
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\') {
                    $escaped = true;
                } elseif ($char === '"') {
                    $quoted = false;
                }
                continue;
            }
            if ($char === '"') {
                $quoted = true;
            } elseif ($char === '{') {
                $depth++;
            } elseif ($char === '}') {
                $depth--;
                if ($depth === 0) {
                    $record = json_decode(substr($bytes, $start, $offset - $start + 1), true);
                    if (!is_array($record) || json_last_error() !== JSON_ERROR_NONE) {
                        return [['malformed_trace' => true]];
                    }
                    $records[] = $record;
                    $start = null;
                }
            }
        }

        return $start === null && !$quoted ? $records : [['malformed_trace' => true]];
    }

    public static function boundedRequestField(string $value, int $limit, string $label): string
    {
        if (strlen($value) > $limit) {
            throw new InvalidArgumentException($label . ' exceeds evidence boundary');
        }

        return $value;
    }

    public static function evidenceBytes(string $directory): int
    {
        $total = 0;
        foreach (new \DirectoryIterator($directory) as $file) {
            if ($file->isFile() && !$file->isLink()) {
                $total += $file->getSize();
            }
        }

        return $total;
    }
}
