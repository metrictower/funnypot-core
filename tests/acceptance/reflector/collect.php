<?php

declare(strict_types=1);

use Funnypot\Core\Tests\Acceptance\ReceiptVerifier;

require __DIR__ . '/ReceiptVerifier.php';

if ($argc !== 1) {
    fwrite(STDERR, "collect.php accepts no arguments\n");
    exit(2);
}

$output = '/output';
$pinsPath = '/opt/reflector/versions.json';
$pins = ReceiptVerifier::loadPins($pinsPath);
$keys = ['nuclei-authorized', 'nuclei-unauthorized', 'dalfox-authorized', 'dalfox-unauthorized'];
$runs = [];
$starts = [];
$ends = [];
$total = 0;

foreach ($keys as $key) {
    $parts = explode('-', $key, 2);
    $scanner = $parts[0];
    $mode = $parts[1];
    $directory = $output . '/' . $key;
    $start = scalarInt($directory . '/started-at');
    $end = scalarInt($directory . '/ended-at');
    $exit = scalarInt($directory . '/exit-status');
    $records = jsonLines($directory . '/records.jsonl');
    $scannerOutput = $scanner === 'nuclei'
        ? jsonLines($directory . '/scanner.jsonl')
        : jsonDocument($directory . '/scanner.json');
    $errors = [];
    if ($scanner === 'nuclei') {
        $errorBytes = @file_get_contents($directory . '/nuclei-errors.log');
        if (is_string($errorBytes) && trim($errorBytes) !== '') {
            foreach (preg_split('/\r?\n/', trim($errorBytes)) as $line) {
                $errors[] = substr($line, 0, 1024);
            }
        }
    }
    if (($scanner === 'nuclei' && $exit !== 0) || ($scanner === 'dalfox' && $exit === 2)) {
        $errors[] = 'scanner hard error (exit ' . $exit . ')';
    }
    if (is_file($directory . '/runner-error')) {
        $errors[] = trim((string) file_get_contents($directory . '/runner-error'));
    }
    $bytes = evidenceBytes($directory);
    $total += $bytes;
    $starts[] = $start;
    $ends[] = $end;
    $runs[$key] = [
        'mode' => $mode,
        'scanner' => $scanner,
        'scanner_version' => (string) $pins[$scanner]['version'],
        'target' => ReceiptVerifier::TARGET,
        'invocation' => jsonDocumentList($directory . '/invocation.json'),
        'started_at' => $start,
        'ended_at' => $end,
        'elapsed_seconds' => max(0, $end - $start),
        'exit_status' => $exit,
        'timed_out' => is_file($directory . '/timed-out'),
        'request_count' => scalarInt($directory . '/request-count'),
        'request_overflow' => is_file($directory . '/request-overflow'),
        'output_bytes' => $bytes,
        'output_truncated' => is_file($directory . '/output-overflow') || is_file($directory . '/evidence-overflow'),
        'errors' => $errors,
        'scanner_output' => $scannerOutput,
        'records' => $records,
    ];
}

$packet = [
    'schema' => ReceiptVerifier::SCHEMA,
    'pins_sha256' => hash_file('sha256', $pinsPath),
    'core_tree_sha256' => scalarHex('/opt/reflector/core-tree.sha256'),
    'template_sha256' => hash_file('sha256', '/opt/reflector/template/reflected-xss.yaml'),
    'started_at' => min($starts),
    'ended_at' => max($ends),
    'elapsed_seconds' => max($ends) - min($starts),
    'total_output_bytes' => $total,
    'runs' => $runs,
];
$encoded = json_encode($packet, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if (!is_string($encoded) || file_put_contents($output . '/receipt.json', $encoded . "\n", LOCK_EX) === false) {
    fwrite(STDERR, "cannot write receipt\n");
    exit(2);
}

try {
    ReceiptVerifier::verifyPinnedArtifacts('/opt/reflector', $pins);
    ReceiptVerifier::verifyPacket($packet, $pins);
} catch (Throwable $error) {
    $message = 'receipt rejected: ' . $error->getMessage();
    file_put_contents($output . '/verification-error.txt', $message . "\n", LOCK_EX);
    fwrite(STDERR, $message . "\n");
    exit(1);
}

fwrite(STDOUT, "reflector acceptance receipt verified\n");

/** @return array<int,mixed> */
function jsonLines(string $path): array
{
    $bytes = @file_get_contents($path);
    if (!is_string($bytes)) {
        return [];
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

/** @return array<string,mixed> */
function jsonDocument(string $path): array
{
    $bytes = @file_get_contents($path);
    if (!is_string($bytes)) {
        return ['malformed_json' => true];
    }
    $decoded = json_decode($bytes, true);

    return is_array($decoded) && json_last_error() === JSON_ERROR_NONE
        ? $decoded
        : ['malformed_json' => true];
}

/** @return string[] */
function jsonDocumentList(string $path): array
{
    $bytes = @file_get_contents($path);
    $decoded = is_string($bytes) ? json_decode($bytes, true) : null;
    if (!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE
        || ($decoded !== [] && array_keys($decoded) !== range(0, count($decoded) - 1))) {
        return [];
    }
    foreach ($decoded as $value) {
        if (!is_string($value)) {
            return [];
        }
    }

    return $decoded;
}

function scalarInt(string $path): int
{
    $value = trim((string) @file_get_contents($path));

    return preg_match('/^[0-9]+$/', $value) === 1 ? (int) $value : 0;
}

function scalarHex(string $path): string
{
    $value = trim((string) @file_get_contents($path));

    return preg_match('/^[0-9a-f]{64}$/', $value) === 1 ? $value : '';
}

function evidenceBytes(string $directory): int
{
    $total = 0;
    foreach (new DirectoryIterator($directory) as $file) {
        if ($file->isFile() && !$file->isLink()) {
            $total += $file->getSize();
        }
    }

    return $total;
}
