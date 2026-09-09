<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Acceptance;

use InvalidArgumentException;

/**
 * Pure verifier for the operator/CI-only reflector acceptance receipt.
 *
 * This class deliberately performs no I/O beyond reading the committed pin packet when asked.
 * It never starts a listener, scanner or container. The live runner emits this closed schema and
 * calls the same verifier before it can publish a successful receipt.
 */
final class ReceiptVerifier
{
    public const SCHEMA = 'funnypot.reflector-acceptance.v1';
    public const PINS_SCHEMA = 'funnypot.reflector-acceptance-pins.v1';
    public const PINS_SHA256 = 'a6de3c0eef1ae9f2daa32b749ef884a0dd1cc6770d2d88c2ad582b0b9b03aaa2';
    public const TARGET = 'http://127.0.0.1:8898/products/quick-search?q=probe';
    public const PATH = '/products/quick-search';
    public const REQUEST_LIMIT = 512;
    public const RUN_SECONDS = 90;
    public const PACKET_SECONDS = 480;
    public const OUTPUT_LIMIT = 16777216;

    /** The ordered Dalfox query probe from the pinned v3.2.2 source. */
    public const DALFOX_SPECIALS = "/\\'\x7b`<>\"();=|\x7d[.:]+,\x24-";

    /** @return array<string,mixed> */
    public static function loadPins(string $path): array
    {
        $bytes = @file_get_contents($path);
        self::check(is_string($bytes), 'pin file unreadable');
        self::check(hash('sha256', $bytes) === self::PINS_SHA256, 'pin file hash mismatch');
        $pins = json_decode($bytes, true);
        self::check(is_array($pins) && json_last_error() === JSON_ERROR_NONE, 'pin file malformed');
        self::validatePins($pins);

        return $pins;
    }

    /** @param array<string,mixed> $pins */
    public static function verifyPinnedArtifacts(string $directory, array $pins): void
    {
        self::validatePins($pins);
        $template = $pins['template'];
        self::verifyFile(
            $directory . '/template/reflected-xss.yaml',
            (int) $template['bytes'],
            (string) $template['sha256'],
            'template'
        );
        foreach ($pins['notices'] as $notice) {
            self::verifyFile(
                $directory . '/' . $notice['path'],
                (int) $notice['bytes'],
                (string) $notice['sha256'],
                'notice ' . $notice['component']
            );
        }
    }

    /** @param array<string,mixed> $packet @param array<string,mixed> $pins */
    public static function verifyPacket(array $packet, array $pins): void
    {
        self::validatePins($pins);
        self::keys($packet, [
            'schema', 'pins_sha256', 'core_tree_sha256', 'compiled_index_sha256',
            'attack_artifact_sha256', 'template_sha256',
            'started_at', 'ended_at', 'elapsed_seconds', 'source_output_bytes',
            'total_output_bytes', 'runs',
        ], 'packet');
        self::check($packet['schema'] === self::SCHEMA, 'wrong receipt schema');
        self::check($packet['pins_sha256'] === self::PINS_SHA256, 'stale pin file hash');
        self::hex($packet['core_tree_sha256'], 'core tree hash');
        self::hex($packet['compiled_index_sha256'], 'compiled index hash');
        self::hex($packet['attack_artifact_sha256'], 'attack artifact hash');
        self::check($packet['template_sha256'] === $pins['template']['sha256'], 'stale template pin');
        self::nonNegativeInt($packet['started_at'], 'packet start');
        self::nonNegativeInt($packet['ended_at'], 'packet end');
        self::nonNegativeInt($packet['elapsed_seconds'], 'packet elapsed');
        self::check($packet['ended_at'] >= $packet['started_at'], 'packet clock reversed');
        self::check($packet['elapsed_seconds'] <= self::PACKET_SECONDS, 'packet timeout');
        self::nonNegativeInt($packet['total_output_bytes'], 'total output bytes');
        self::check($packet['total_output_bytes'] <= self::OUTPUT_LIMIT, 'evidence output overflow');
        self::nonNegativeInt($packet['source_output_bytes'], 'source output bytes');
        self::check(is_array($packet['runs']), 'runs must be an object');
        self::keys($packet['runs'], [
            'nuclei-authorized', 'nuclei-unauthorized', 'dalfox-authorized', 'dalfox-unauthorized',
        ], 'runs');

        $sum = 0;
        foreach ($packet['runs'] as $key => $run) {
            self::check(is_array($run), 'run malformed: ' . $key);
            self::verifyRun((string) $key, $run, $pins);
            foreach (['core_tree_sha256', 'compiled_index_sha256', 'attack_artifact_sha256', 'template_sha256'] as $hashField) {
                self::check($run[$hashField] === $packet[$hashField], 'run/packet hash mismatch: ' . $hashField);
            }
            $sum += $run['output_bytes'];
        }
        self::check($sum === $packet['source_output_bytes'], 'source output byte count mismatch');

        self::verifyNuclei($packet['runs']['nuclei-authorized'], true);
        self::verifyNuclei($packet['runs']['nuclei-unauthorized'], false);
        self::verifyDalfox($packet['runs']['dalfox-authorized'], true);
        self::verifyDalfox($packet['runs']['dalfox-unauthorized'], false);
        $encoded = json_encode($packet, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        self::check(is_string($encoded), 'receipt cannot be encoded');
        self::check($packet['total_output_bytes'] === $packet['source_output_bytes'] + strlen($encoded) + 1, 'receipt-inclusive output byte count mismatch');
    }

    /** @param array<string,mixed> $run @param array<string,mixed> $pins */
    private static function verifyRun(string $key, array $run, array $pins): void
    {
        self::keys($run, [
            'mode', 'scanner', 'scanner_version', 'scanner_archive_sha256', 'core_tree_sha256',
            'compiled_index_sha256', 'attack_artifact_sha256', 'template_sha256',
            'target', 'invocation', 'started_at', 'ended_at',
            'elapsed_seconds', 'exit_status', 'timed_out', 'request_count', 'request_overflow',
            'output_bytes', 'output_truncated', 'errors', 'scanner_error_log_present',
            'scanner_trace', 'scanner_output', 'records',
        ], 'run ' . $key);
        $parts = explode('-', $key, 2);
        self::check(count($parts) === 2, 'bad run key');
        $scanner = $parts[0];
        $mode = $parts[1];
        self::check($run['scanner'] === $scanner, 'scanner/key mismatch');
        self::check($run['mode'] === $mode, 'mode/key mismatch');
        self::check($run['scanner_version'] === $pins[$scanner]['version'], 'stale scanner version');
        self::check($run['scanner_archive_sha256'] === $pins[$scanner]['archive_sha256'], 'stale scanner archive hash');
        self::hex($run['core_tree_sha256'], 'run core tree hash');
        self::hex($run['compiled_index_sha256'], 'run compiled index hash');
        self::hex($run['attack_artifact_sha256'], 'run attack artifact hash');
        self::check($run['template_sha256'] === $pins['template']['sha256'], 'run template hash mismatch');
        self::check($run['target'] === self::TARGET, 'wrong target');
        self::check(is_array($run['invocation']) && self::isList($run['invocation']), 'invocation must be a list');
        self::check($run['invocation'] === self::expectedInvocation($scanner, $key), 'scanner invocation drift');
        self::nonNegativeInt($run['started_at'], 'run start');
        self::nonNegativeInt($run['ended_at'], 'run end');
        self::nonNegativeInt($run['elapsed_seconds'], 'run elapsed');
        self::check($run['ended_at'] >= $run['started_at'], 'run clock reversed');
        self::check($run['elapsed_seconds'] <= self::RUN_SECONDS, 'scanner timeout');
        self::check($run['timed_out'] === false, 'scanner timed out');
        self::nonNegativeInt($run['request_count'], 'request count');
        self::check($run['request_count'] > 0, 'scanner made no observed request');
        self::check($run['request_count'] <= self::REQUEST_LIMIT, 'request overflow');
        self::check($run['request_overflow'] === false, 'request overflow flag');
        self::nonNegativeInt($run['output_bytes'], 'run output bytes');
        self::check($run['output_bytes'] <= self::OUTPUT_LIMIT, 'run output overflow');
        self::check($run['output_truncated'] === false, 'scanner output truncated');
        self::check(is_array($run['errors']) && self::isList($run['errors']) && $run['errors'] === [], 'scanner errors present');
        self::check(is_array($run['scanner_trace']) && self::isList($run['scanner_trace']), 'scanner trace malformed');
        self::check(is_array($run['records']) && self::isList($run['records']), 'records must be a list');
        self::check(count($run['records']) === $run['request_count'], 'request count/record mismatch');
        foreach ($run['records'] as $index => $record) {
            self::check(is_array($record), 'malformed response record');
            self::verifyRecord($record, $index);
        }
        self::verifyNoUnauthorizedRawReflection($run);
    }

    /** @param array<string,mixed> $record */
    private static function verifyRecord(array $record, int $index): void
    {
        self::check(isset($record['kind']) && is_string($record['kind']), 'record kind missing');
        if ($record['kind'] === 'response') {
            self::keys($record, ['kind', 'sequence', 'method', 'path', 'query', 'query_value', 'status', 'owner', 'headers', 'body'], 'response record');
            self::check(is_string($record['owner']) && in_array($record['owner'], [
                'attack-xss-baseline', 'attack-xss', 'attack-xss-escalation',
            ], true), 'unknown response owner');
            self::check(is_array($record['headers']), 'response headers malformed');
            self::check(is_string($record['body']), 'response body malformed');
        } elseif ($record['kind'] === 'core-null') {
            self::keys($record, ['kind', 'sequence', 'method', 'path', 'query', 'query_value'], 'core-null record');
        } elseif ($record['kind'] === 'router-reject') {
            self::keys($record, ['kind', 'sequence', 'method', 'path', 'query'], 'router-reject record');
            $owned = $record['path'] === self::PATH || $record['path'] === self::PATH . '/';
            self::check(!$owned || $record['method'] !== 'GET', 'owned GET mislabeled router reject');
        } else {
            throw new InvalidArgumentException('unknown record kind');
        }
        self::nonNegativeInt($record['sequence'], 'record sequence');
        self::check($record['sequence'] === $index + 1, 'record order mismatch');
        self::check(is_string($record['method']), 'request method malformed');
        if ($record['kind'] !== 'router-reject') {
            self::check($record['method'] === 'GET', 'unexpected request method');
        }
        self::check(is_string($record['path']) && is_string($record['query']), 'record request malformed');

        if ($record['kind'] !== 'router-reject') {
            self::check($record['path'] === self::PATH || $record['path'] === self::PATH . '/', 'wrong owned route');
            self::check(is_string($record['query_value']), 'query value missing');
        }

        if ($record['kind'] !== 'response') {
            return;
        }
        $value = $record['query_value'];
        if ($record['owner'] === 'attack-xss-baseline') {
            self::check(preg_match('/^[A-Za-z0-9]{1,64}$/', $value) === 1, 'baseline owner/payload mismatch');
            self::check(strpos($record['body'], $value) !== false, 'baseline value not reflected');
        } elseif ($record['owner'] === 'attack-xss') {
            self::check(preg_match('/<[^>]*dlx[0-9a-f]{8}[^>]*>/i', $value, $m) === 1, 'legacy owner/payload mismatch');
            self::check(strpos($record['body'], $m[0]) !== false, 'legacy matched tag not reflected');
        } else {
            self::check(self::isSpecialProbe($value) || self::numericBreakout($value) !== null, 'escalation owner/payload mismatch');
            self::check(strpos($record['body'], $value) !== false, 'escalation payload not reflected whole');
            self::verifyEscalationHeaders($record['headers']);
        }
    }

    /** @param array<string,mixed> $run */
    private static function verifyNuclei(array $run, bool $authorized): void
    {
        self::check(is_array($run['scanner_output']) && self::isList($run['scanner_output']), 'nuclei output must be JSONL records');
        self::check($run['scanner_error_log_present'] === true, 'nuclei error log missing');
        self::check(count($run['scanner_trace']) > 0, 'nuclei trace missing');
        self::check(count($run['scanner_trace']) === $run['request_count'], 'nuclei trace/request count mismatch');
        foreach ($run['scanner_trace'] as $trace) {
            self::check(is_array($trace), 'nuclei trace record malformed');
            self::check(($trace['error'] ?? null) === 'none', 'nuclei trace contains request error');
            self::check(($trace['address'] ?? null) === '127.0.0.1:8898', 'nuclei trace escaped loopback target');
            $input = isset($trace['input']) && is_string($trace['input']) ? parse_url($trace['input']) : false;
            self::check(is_array($input)
                && ($input['scheme'] ?? null) === 'http'
                && ($input['host'] ?? null) === '127.0.0.1'
                && ($input['port'] ?? null) === 8898, 'nuclei trace target malformed');
            self::check(($trace['template'] ?? null) === '/opt/reflector/template/reflected-xss.yaml', 'nuclei trace template drift');
            $correlated = false;
            foreach ($run['records'] as $record) {
                if (($input['path'] ?? null) === $record['path']
                    && (isset($input['query']) ? $input['query'] : '') === $record['query']) {
                    $correlated = true;
                    break;
                }
            }
            self::check($correlated, 'nuclei trace lacks responder record');
        }
        if ($authorized) {
            self::check($run['exit_status'] === 0, 'nuclei hard error');
            self::check(count($run['scanner_output']) > 0, 'nuclei produced no pinned finding');
            $correlated = false;
            foreach ($run['scanner_output'] as $finding) {
                self::check(is_array($finding), 'malformed nuclei result');
                self::check(($finding['template-id'] ?? null) === 'reflected-xss', 'wrong nuclei template');
                self::check(($finding['type'] ?? null) === 'http', 'wrong nuclei result type');
                self::check(($finding['matcher-status'] ?? null) === true, 'nuclei matcher did not pass');
                self::check(($finding['is_fuzzing_result'] ?? null) === true, 'nuclei result is not fuzzing evidence');
                self::check(is_string($finding['request'] ?? null) && is_string($finding['response'] ?? null), 'nuclei request/response missing');
                $matched = isset($finding['matched-at']) && is_string($finding['matched-at']) ? parse_url($finding['matched-at']) : false;
                self::check(is_array($matched)
                    && ($matched['scheme'] ?? null) === 'http'
                    && ($matched['host'] ?? null) === '127.0.0.1'
                    && ($matched['port'] ?? null) === 8898
                    && (($matched['path'] ?? null) === self::PATH || ($matched['path'] ?? null) === self::PATH . '/'), 'nuclei matched-at escaped target');
                $payload = self::numericBreakout(rawurldecode($finding['request']));
                self::check($payload !== null, 'nuclei numeric breakout missing');
                self::check(strpos($finding['response'], $payload) !== false, 'nuclei output response lacks breakout');
                foreach ($run['records'] as $record) {
                    if ($record['kind'] === 'response'
                        && $record['owner'] === 'attack-xss-escalation'
                        && strpos($record['query_value'], $payload) !== false
                        && strpos($record['body'], $payload) !== false) {
                        $correlated = true;
                    }
                }
            }
            self::check($correlated, 'nuclei finding lacks responder correlation');
        } else {
            self::check($run['exit_status'] === 0, 'unauthorized nuclei hard error');
            self::check($run['scanner_output'] === [], 'unauthorized nuclei output not empty');
            self::check(self::hasClosedRawProbe($run), 'unauthorized nuclei control did not exercise the raw gate');
        }
    }

    /** @param array<string,mixed> $run */
    private static function verifyDalfox(array $run, bool $authorized): void
    {
        $output = $run['scanner_output'];
        self::check($run['scanner_error_log_present'] === false, 'unexpected dalfox error-log claim');
        self::check($run['scanner_trace'] === [], 'unexpected dalfox trace claim');
        self::check(is_array($output), 'dalfox output malformed');
        self::keys($output, ['meta', 'findings'], 'dalfox output');
        self::check(is_array($output['meta']) && is_array($output['findings']), 'dalfox output fields malformed');
        $meta = $output['meta'];
        self::check(($meta['dalfox_version'] ?? null) === $run['scanner_version'], 'dalfox output version mismatch');
        self::check(($meta['targets'] ?? null) === [self::TARGET], 'dalfox output target mismatch');
        self::check(($meta['incomplete'] ?? null) === false, 'dalfox scan incomplete');
        self::check(isset($meta['target_summary']) && is_array($meta['target_summary']) && count($meta['target_summary']) === 1, 'dalfox target summary missing');
        $summary = $meta['target_summary'][0];
        self::check(is_array($summary) && ($summary['target'] ?? null) === self::TARGET, 'dalfox summary target mismatch');
        self::check(!isset($summary['error_code']), 'dalfox target error');
        self::check(($meta['findings_count'] ?? null) === count($output['findings']), 'dalfox finding count mismatch');
        foreach ($output['findings'] as $finding) {
            self::check(is_array($finding), 'dalfox finding malformed');
            self::check(in_array($finding['type'] ?? null, ['R', 'V'], true), 'dalfox finding type missing');
            self::check(in_array($finding['detection_method'] ?? null, ['reflection', 'dom-verification'], true), 'dalfox detection method missing');
            self::check(array_key_exists('confidence', $finding)
                && in_array($finding['confidence'], [null, 'low', 'high'], true), 'dalfox confidence missing');
            self::check(is_string($finding['request'] ?? null) && is_string($finding['response'] ?? null), 'dalfox finding request/response missing');
            self::check(preg_match('/dlx[0-9a-f]{8}/', rawurldecode($finding['request']), $marker) === 1, 'dalfox finding marker missing');
            self::check(strpos($finding['response'], $marker[0]) !== false, 'dalfox finding response lacks marker');
            $correlated = false;
            foreach ($run['records'] as $record) {
                if ($record['kind'] === 'response'
                    && strpos($record['query_value'], $marker[0]) !== false
                    && strpos($record['body'], $marker[0]) !== false) {
                    $correlated = true;
                    break;
                }
            }
            self::check($correlated, 'dalfox finding lacks responder correlation');
        }
        if ($authorized) {
            self::check(count($output['findings']) > 0, 'dalfox produced no final R/V evidence');
        }
        if (count($output['findings']) > 0) {
            self::check($run['exit_status'] === 1, 'dalfox findings exit mismatch');
            self::check(($summary['status'] ?? null) === 'findings', 'dalfox summary did not report findings');
        } else {
            self::check($run['exit_status'] === 0, 'dalfox clean exit mismatch');
            self::check(($summary['status'] ?? null) === 'clean', 'dalfox summary did not report clean');
        }

        if (!$authorized) {
            self::check(self::hasClosedRawProbe($run), 'unauthorized dalfox control did not exercise the raw gate');
            return;
        }

        $discovery = null;
        $special = null;
        $tag = null;
        foreach ($run['records'] as $index => $record) {
            $value = isset($record['query_value']) ? $record['query_value'] : '';
            if ($discovery === null && preg_match('/dlx[0-9a-f]{8}dlxmid[0-9a-f]{8}xld[0-9a-f]{8}/', $value) === 1) {
                $discovery = $index;
                self::check($record['kind'] === 'response' && $record['owner'] === 'attack-xss-baseline', 'discovery ownership mismatch');
            }
            if ($special === null && self::isSpecialProbe($value)) {
                $special = $index;
                self::check($record['kind'] === 'response' && $record['owner'] === 'attack-xss-escalation', 'special probe was not escalation-reflected');
            }
            if ($tag === null && preg_match('/<[^>]*dlx[0-9a-f]{8}[^>]*>/i', $value) === 1) {
                $tag = $index;
            }
        }
        self::check($discovery !== null, 'dalfox discovery stage missing');
        self::check($special !== null, 'dalfox special-character stage missing');
        self::check($tag !== null, 'dalfox generated-tag stage missing');
        self::check($discovery < $special && $special < $tag, 'dalfox request stages out of order');
    }

    /** @param array<string,mixed> $run */
    private static function verifyNoUnauthorizedRawReflection(array $run): void
    {
        if ($run['mode'] !== 'unauthorized') {
            return;
        }
        foreach ($run['records'] as $record) {
            if ($record['kind'] !== 'response') {
                continue;
            }
            self::check($record['owner'] !== 'attack-xss' && $record['owner'] !== 'attack-xss-escalation', 'unauthorized gated owner served');
            $value = $record['query_value'];
            if (self::isSpecialProbe($value) || self::numericBreakout($value) !== null || preg_match('/<[^>]*dlx[0-9a-f]{8}[^>]*>/i', $value) === 1) {
                self::check(strpos($record['body'], $value) === false, 'unauthorized raw input reflected');
            }
        }
    }

    /** @param array<string,mixed> $run */
    private static function hasClosedRawProbe(array $run): bool
    {
        foreach ($run['records'] as $record) {
            if ($record['kind'] === 'router-reject') {
                continue;
            }
            $value = $record['query_value'];
            if (($record['kind'] === 'core-null')
                && (self::isSpecialProbe($value) || self::numericBreakout($value) !== null || preg_match('/<[^>]*dlx[0-9a-f]{8}[^>]*>/i', $value) === 1)) {
                return true;
            }
        }

        return false;
    }

    private static function isSpecialProbe(string $value): bool
    {
        return strpos($value, self::DALFOX_SPECIALS) !== false
            && preg_match('/dlx[0-9a-f]{8}.*xld[0-9a-f]{8}/s', $value) === 1;
    }

    private static function numericBreakout(string $value): ?string
    {
        if (preg_match('/[\x27]\"><[0-9]{5}>/', $value, $match) !== 1) {
            return null;
        }

        return $match[0];
    }

    /** @param array<string,mixed> $headers */
    private static function verifyEscalationHeaders(array $headers): void
    {
        $expected = [
            'Content-Type' => 'text/html; charset=utf-8',
            'Content-Security-Policy' => "sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'no-referrer',
            'Cross-Origin-Resource-Policy' => 'same-origin',
            'Cross-Origin-Opener-Policy' => 'same-origin',
            'Cache-Control' => 'no-store',
        ];
        foreach ($expected as $name => $value) {
            self::check(($headers[$name] ?? null) === $value, 'missing/wrong escalation header: ' . $name);
        }
    }

    /** @return string[] */
    private static function expectedInvocation(string $scanner, string $key): array
    {
        $dir = '/output/' . $key;
        if ($scanner === 'nuclei') {
            return [
                '/opt/reflector/bin/nuclei', '-u', self::TARGET,
                '-t', '/opt/reflector/template/reflected-xss.yaml', '-dast',
                '-no-interactsh', '-disable-update-check', '-disable-redirects',
                '-jsonl', '-no-color', '-concurrency', '1', '-bulk-size', '1',
                '-timeout', '5', '-retries', '0', '-no-stdin',
                '-error-log', $dir . '/nuclei-errors.log',
                '-trace-log', $dir . '/nuclei-trace.log',
                '-output', $dir . '/scanner.jsonl',
            ];
        }

        return [
            '/opt/reflector/bin/dalfox', 'scan', self::TARGET,
            '--format', 'json', '--output', $dir . '/scanner.json', '--include-all',
            '--no-color', '--workers', '1', '--max-concurrent-targets', '1',
            '--max-targets-per-host', '1', '--skip-mining', '--skip-reflection-header',
            '--skip-reflection-cookie', '--skip-reflection-path', '--skip-ast-analysis',
            '--skip-waf-probe', '--waf-bypass', 'off', '--timeout', '5',
            '--scan-timeout', '60', '--retries', '0', '--max-payloads-per-param', '64',
        ];
    }

    /** @param array<string,mixed> $pins */
    private static function validatePins(array $pins): void
    {
        self::keys($pins, ['schema', 'platform', 'php_image', 'nuclei', 'dalfox', 'template', 'notices'], 'pins');
        self::check($pins['schema'] === self::PINS_SCHEMA, 'wrong pin schema');
        self::check($pins['platform'] === 'linux/amd64', 'wrong pin platform');
        self::keys($pins['php_image'], ['reference', 'index_digest', 'manifest_digest', 'metadata_url'], 'php image pin');
        self::check($pins['php_image']['reference'] === 'php:8.3-cli-bookworm', 'wrong PHP image');
        self::check($pins['php_image']['index_digest'] === 'sha256:177529735599a8244b2c903522f029839dce1c2ac4be122fdc00ada4b45a20e4', 'wrong PHP index pin');
        self::check($pins['php_image']['manifest_digest'] === 'sha256:172e13bc72d4fe6503db39b3ecad301406492ae661e1803138fa45eafc7491f2', 'wrong PHP manifest pin');
        self::digest($pins['php_image']['index_digest'], 'PHP index digest');
        self::digest($pins['php_image']['manifest_digest'], 'PHP manifest digest');
        foreach (['nuclei', 'dalfox'] as $tool) {
            self::keys($pins[$tool], ['version', 'source_ref', 'source_url', 'archive_name', 'archive_url', 'archive_bytes', 'archive_sha256', 'archive_member'], $tool . ' pin');
            self::check(is_string($pins[$tool]['version']) && $pins[$tool]['version'] !== '', $tool . ' version missing');
            self::commit($pins[$tool]['source_ref'], $tool . ' source ref');
            self::hex($pins[$tool]['archive_sha256'], $tool . ' archive hash');
            self::nonNegativeInt($pins[$tool]['archive_bytes'], $tool . ' archive bytes');
            self::check($pins[$tool]['archive_bytes'] > 0, $tool . ' archive bytes empty');
        }
        self::check($pins['nuclei']['version'] === '3.11.1', 'wrong nuclei version pin');
        self::check($pins['nuclei']['source_ref'] === 'a8c88feb4a1c8e961b7902534ce3af97e9d524a4', 'wrong nuclei source pin');
        self::check($pins['nuclei']['archive_sha256'] === 'ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6', 'wrong nuclei archive pin');
        self::check($pins['dalfox']['version'] === '3.2.2', 'wrong dalfox version pin');
        self::check($pins['dalfox']['source_ref'] === '7bb684fdf48959d10c6a6ac24d4a190361c58c8f', 'wrong dalfox source pin');
        self::check($pins['dalfox']['archive_sha256'] === '9ade9e1215553826e15273741931011fbc5b9e17ea1ea485e714389b8cfbb50d', 'wrong dalfox archive pin');
        self::keys($pins['template'], ['source_ref', 'source_path', 'source_url', 'bytes', 'sha256'], 'template pin');
        self::commit($pins['template']['source_ref'], 'template source ref');
        self::hex($pins['template']['sha256'], 'template hash');
        self::check($pins['template']['source_ref'] === 'ca9197a381d96099b4ffbe36367e35c6a38d253f', 'wrong template source pin');
        self::check($pins['template']['sha256'] === 'f2b84b2f05859230ad6ad76c6a8774fea7cad552cb6f532883332ae21d48b960', 'wrong template hash pin');
        self::nonNegativeInt($pins['template']['bytes'], 'template bytes');
        self::check(is_array($pins['notices']) && self::isList($pins['notices']) && count($pins['notices']) === 3, 'notice pins malformed');
        $components = [];
        foreach ($pins['notices'] as $notice) {
            self::keys($notice, ['component', 'path', 'bytes', 'sha256'], 'notice pin');
            self::check(is_string($notice['component']) && $notice['component'] !== '', 'notice component missing');
            self::check(strpos($notice['path'], '..') === false && strpos($notice['path'], '/') !== 0, 'unsafe notice path');
            self::nonNegativeInt($notice['bytes'], 'notice bytes');
            self::hex($notice['sha256'], 'notice hash');
            self::check(!isset($components[$notice['component']]), 'duplicate notice component');
            $components[$notice['component']] = true;
        }
        self::check(array_keys($components) === ['nuclei', 'dalfox', 'nuclei-templates'], 'notice component set mismatch');
    }

    private static function verifyFile(string $path, int $bytes, string $sha256, string $label): void
    {
        self::check(is_file($path) && !is_link($path), $label . ' missing');
        self::check(filesize($path) === $bytes, $label . ' byte count mismatch');
        self::check(hash_file('sha256', $path) === $sha256, $label . ' hash mismatch');
    }

    /** @param array<mixed> $value @param string[] $expected */
    private static function keys(array $value, array $expected, string $label): void
    {
        $actual = array_keys($value);
        sort($actual);
        sort($expected);
        self::check($actual === $expected, $label . ' keys mismatch');
    }

    /** @param mixed $value */
    private static function nonNegativeInt($value, string $label): void
    {
        self::check(is_int($value) && $value >= 0, $label . ' must be a non-negative integer');
    }

    /** @param mixed $value */
    private static function hex($value, string $label): void
    {
        self::check(is_string($value) && preg_match('/^[0-9a-f]{64}$/', $value) === 1, $label . ' malformed');
    }

    /** @param mixed $value */
    private static function commit($value, string $label): void
    {
        self::check(is_string($value) && preg_match('/^[0-9a-f]{40}$/', $value) === 1, $label . ' malformed');
    }

    /** @param mixed $value */
    private static function digest($value, string $label): void
    {
        self::check(is_string($value) && preg_match('/^sha256:[0-9a-f]{64}$/', $value) === 1, $label . ' malformed');
    }

    /** @param array<mixed> $value */
    private static function isList(array $value): bool
    {
        return $value === [] || array_keys($value) === range(0, count($value) - 1);
    }

    private static function check(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new InvalidArgumentException($message);
        }
    }
}
