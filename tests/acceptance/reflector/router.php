<?php

declare(strict_types=1);

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Http\ResponseEmitter;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Tests\Acceptance\EvidenceFiles;

const REFLECT_PATH = '/products/quick-search';
const REFLECT_REQUEST_LIMIT = 512;
const REFLECT_RECORD_LIMIT = 262144;

require __DIR__ . '/autoload.php';
require __DIR__ . '/EvidenceFiles.php';

$runDirectory = getenv('REFLECT_RUN_DIR');
$mode = getenv('REFLECT_MODE');
if (!is_string($runDirectory) || strpos($runDirectory, '/output/') !== 0
    || ($mode !== 'authorized' && $mode !== 'unauthorized')) {
    http_response_code(500);
    echo "fixture configuration error\n";

    return true;
}

$sequence = nextSequence($runDirectory);
if ($sequence > REFLECT_REQUEST_LIMIT) {
    @file_put_contents($runDirectory . '/request-overflow', "1\n", LOCK_EX);
    http_response_code(429);
    header('Content-Type: text/plain');
    echo "request budget exhausted\n";

    return true;
}

$target = isset($_SERVER['REQUEST_URI']) && is_string($_SERVER['REQUEST_URI'])
    ? $_SERVER['REQUEST_URI']
    : '/';
$question = strpos($target, '?');
$path = $question === false ? $target : substr($target, 0, $question);
$query = $question === false ? '' : substr($target, $question + 1);
$method = isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : 'GET';
try {
    $path = EvidenceFiles::boundedRequestField($path, 4096, 'request path');
    $query = EvidenceFiles::boundedRequestField($query, 4096, 'request query');
} catch (InvalidArgumentException $error) {
    @file_put_contents($runDirectory . '/evidence-overflow', "1\n", LOCK_EX);
    http_response_code(413);
    header('Content-Type: text/plain');
    echo "request evidence boundary exceeded\n";

    return true;
}

if ($method !== 'GET' || ($path !== REFLECT_PATH && $path !== REFLECT_PATH . '/')) {
    $record = [
        'kind' => 'router-reject',
        'sequence' => $sequence,
        'method' => $method,
        'path' => $path,
        'query' => $query,
    ];
    requireRecord($runDirectory, $record);
    http_response_code(404);
    header('Content-Type: text/plain');
    echo "Not Found\n";

    return true;
}

try {
    $queryValue = queryValue($query, 'q');
} catch (InvalidArgumentException $error) {
    @file_put_contents($runDirectory . '/evidence-overflow', "1\n", LOCK_EX);
    http_response_code(413);
    header('Content-Type: text/plain');
    echo "request evidence boundary exceeded\n";

    return true;
}
$config = new Config('respond');
$config->gate = static function (RequestContext $request): bool { return true; };
$config->personaSeed = static function (RequestContext $request): string { return 'reflector-acceptance-fixed-persona'; };
$config->attackEmulation = true;
$config->isolatedOrigin = true;
if ($mode === 'authorized') {
    $config->reflectorAuthorizer = static function (RequestContext $request, string $class): bool { return true; };
}

$request = new RequestContext($method, $path, $query, [], null, '127.0.0.1:8898', 'http', '1.1');
$response = Honeypot::default($config)->respond($request);
$base = [
    'sequence' => $sequence,
    'method' => $method,
    'path' => $path,
    'query' => $query,
    'query_value' => $queryValue,
];

if ($response === null) {
    requireRecord($runDirectory, array_merge(['kind' => 'core-null'], $base));
    http_response_code(404);
    header('Content-Type: text/plain');
    echo "Not Found\n";

    return true;
}

$headers = [];
foreach (ResponseEmitter::headerLines($response) as $header) {
    $colon = strpos($header[0], ':');
    if ($colon !== false) {
        $headers[substr($header[0], 0, $colon)] = ltrim(substr($header[0], $colon + 1));
    }
}
$owner = $response->servedBy === null ? '' : $response->servedBy->ruleId;
$record = array_merge([
    'kind' => 'response',
], $base, [
    'status' => $response->status,
    'owner' => $owner,
    'headers' => $headers,
    'body' => $response->body,
]);
requireRecord($runDirectory, $record);
ResponseEmitter::emit($response);

return true;

function nextSequence(string $directory): int
{
    $handle = @fopen($directory . '/request-count', 'c+');
    if ($handle === false || !flock($handle, LOCK_EX)) {
        throw new RuntimeException('cannot lock request counter');
    }
    $raw = stream_get_contents($handle);
    $value = is_string($raw) && preg_match('/^[0-9]+$/', trim($raw)) === 1 ? (int) trim($raw) : 0;
    $value++;
    rewind($handle);
    if (!ftruncate($handle, 0) || fwrite($handle, (string) $value) === false || !fflush($handle)) {
        flock($handle, LOCK_UN);
        fclose($handle);
        throw new RuntimeException('cannot update request counter');
    }
    flock($handle, LOCK_UN);
    fclose($handle);

    return $value;
}

/** @param array<string,mixed> $record */
function requireRecord(string $directory, array $record): void
{
    $json = json_encode($record, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        throw new RuntimeException('cannot encode evidence');
    }
    $path = $directory . '/records.jsonl';
    $handle = @fopen($path, 'ab');
    if ($handle === false || !flock($handle, LOCK_EX)) {
        throw new RuntimeException('cannot lock evidence');
    }
    $size = fstat($handle);
    $next = $json . "\n";
    if (!is_array($size) || $size['size'] + strlen($next) > REFLECT_RECORD_LIMIT
        || fwrite($handle, $next) !== strlen($next) || !fflush($handle)) {
        @file_put_contents($directory . '/evidence-overflow', "1\n", LOCK_EX);
        flock($handle, LOCK_UN);
        fclose($handle);
        throw new RuntimeException('evidence budget exhausted');
    }
    flock($handle, LOCK_UN);
    fclose($handle);
}

function queryValue(string $query, string $wanted): string
{
    $examined = 0;
    foreach (explode('&', $query, 65) as $pair) {
        $examined++;
        if ($examined > 64) {
            break;
        }
        $equals = strpos($pair, '=');
        $name = $equals === false ? $pair : substr($pair, 0, $equals);
        if (urldecode($name) !== $wanted) {
            continue;
        }

        return EvidenceFiles::boundedRequestField(
            urldecode($equals === false ? '' : substr($pair, $equals + 1)),
            2048,
            'decoded query value'
        );
    }

    return '';
}
