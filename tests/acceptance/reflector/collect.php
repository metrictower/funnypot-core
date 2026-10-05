<?php

declare(strict_types=1);

use Funnypot\Core\Tests\Acceptance\ReceiptVerifier;
use Funnypot\Core\Tests\Acceptance\EvidenceFiles;

require __DIR__ . '/ReceiptVerifier.php';
require __DIR__ . '/EvidenceFiles.php';

if ($argc !== 1) {
    fwrite(STDERR, "collect.php accepts no arguments\n");
    exit(2);
}

$output = '/output';
$pinsPath = '/opt/reflector/versions.json';
$pins = ReceiptVerifier::loadPins($pinsPath);
$keys = ['nuclei-authorized', 'nuclei-unauthorized', 'dalfox-authorized', 'dalfox-unauthorized'];
$coreTreeHash = scalarHex('/opt/reflector/core-tree.sha256');
$compiledIndexHash = hash_file('sha256', '/workspace/resources/compiled/nuclei-index.full.php');
$attackArtifactHash = hash_file('sha256', '/workspace/resources/compiled/funnypot-attack.php');
$templateHash = hash_file('sha256', '/opt/reflector/template/reflected-xss.yaml');
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
    $records = EvidenceFiles::jsonLines($directory . '/records.jsonl');
    $scannerOutput = $scanner === 'nuclei'
        ? EvidenceFiles::jsonLines($directory . '/scanner.jsonl')
        : jsonDocument($directory . '/scanner.json');
    if ($scanner === 'dalfox') {
        $scannerOutput = normalizeDalfox($scannerOutput);
    }
    $scannerTrace = $scanner === 'nuclei'
        ? EvidenceFiles::jsonSequence($directory . '/nuclei-trace.log')
        : [];
    $errors = [];
    if ($scanner === 'nuclei') {
        $errorBytes = is_file($directory . '/nuclei-errors.log')
            ? file_get_contents($directory . '/nuclei-errors.log')
            : false;
        if (!is_string($errorBytes)) {
            $errors[] = 'nuclei error log missing';
        } elseif (trim($errorBytes) !== '') {
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
    $bytes = EvidenceFiles::evidenceBytes($directory);
    $total += $bytes;
    $starts[] = $start;
    $ends[] = $end;
    $runs[$key] = [
        'mode' => $mode,
        'scanner' => $scanner,
        'scanner_version' => (string) $pins[$scanner]['version'],
        'scanner_archive_sha256' => (string) $pins[$scanner]['archive_sha256'],
        'core_tree_sha256' => $coreTreeHash,
        'compiled_index_sha256' => $compiledIndexHash,
        'attack_artifact_sha256' => $attackArtifactHash,
        'template_sha256' => $templateHash,
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
        'scanner_error_log_present' => $scanner === 'nuclei' && is_file($directory . '/nuclei-errors.log'),
        'scanner_trace' => $scannerTrace,
        'scanner_output' => $scannerOutput,
        'records' => $records,
    ];
}

$packet = [
    'schema' => ReceiptVerifier::SCHEMA,
    'pins_sha256' => hash_file('sha256', $pinsPath),
    'core_tree_sha256' => $coreTreeHash,
    'compiled_index_sha256' => $compiledIndexHash,
    'attack_artifact_sha256' => $attackArtifactHash,
    'template_sha256' => $templateHash,
    'started_at' => min($starts),
    'ended_at' => max($ends),
    'elapsed_seconds' => max($ends) - min($starts),
    'source_output_bytes' => $total,
    'total_output_bytes' => 0,
    'runs' => $runs,
];
$encoded = '';
for ($attempt = 0; $attempt < 4; $attempt++) {
    $encoded = json_encode($packet, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($encoded)) {
        break;
    }
    $inclusive = $total + strlen($encoded) + 1;
    if ($packet['total_output_bytes'] === $inclusive) {
        break;
    }
    $packet['total_output_bytes'] = $inclusive;
}
if ($packet['total_output_bytes'] > ReceiptVerifier::OUTPUT_LIMIT) {
    $message = "receipt-inclusive evidence exceeds 16 MiB\n";
    file_put_contents($output . '/verification-error.txt', $message, LOCK_EX);
    fwrite(STDERR, $message);
    exit(1);
}
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

/** @param array<string,mixed> $output @return array<string,mixed> */
function normalizeDalfox(array $output): array
{
    if (!isset($output['findings']) || !is_array($output['findings'])) {
        return $output;
    }
    foreach ($output['findings'] as &$finding) {
        if (is_array($finding) && !array_key_exists('confidence', $finding)) {
            $finding['confidence'] = null;
        }
    }
    unset($finding);

    return $output;
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
