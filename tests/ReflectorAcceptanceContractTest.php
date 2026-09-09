<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Tests\Acceptance\ReceiptVerifier;
use Funnypot\Core\Tests\Acceptance\EvidenceFiles;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/acceptance/reflector/ReceiptVerifier.php';
require_once __DIR__ . '/acceptance/reflector/EvidenceFiles.php';

final class ReflectorAcceptanceContractTest extends TestCase
{
    /** @var array<string,mixed> */
    private $pins;

    protected function setUp(): void
    {
        $this->pins = ReceiptVerifier::loadPins(__DIR__ . '/acceptance/reflector/versions.json');
    }

    public function test_committed_pin_packet_and_unmodified_template_are_exact(): void
    {
        ReceiptVerifier::verifyPinnedArtifacts(__DIR__ . '/acceptance/reflector', $this->pins);
        self::addToAssertionCount(1);
    }

    public function test_complete_receipt_is_accepted(): void
    {
        ReceiptVerifier::verifyPacket($this->packet(), $this->pins);
        self::addToAssertionCount(1);
    }

    public function test_missing_stage_and_wrong_order_are_rejected(): void
    {
        $missing = $this->packet();
        array_splice($missing['runs']['dalfox-authorized']['records'], 1, 1);
        $missing['runs']['dalfox-authorized']['request_count']--;
        $missing['runs']['dalfox-authorized']['records'][1]['sequence'] = 2;
        $this->rejects($missing, 'special-character stage missing');

        $wrong = $this->packet();
        $records = $wrong['runs']['dalfox-authorized']['records'];
        $wrong['runs']['dalfox-authorized']['records'] = [$records[1], $records[0], $records[2]];
        foreach ($wrong['runs']['dalfox-authorized']['records'] as $i => &$record) {
            $record['sequence'] = $i + 1;
        }
        unset($record);
        $this->rejects($wrong, 'dalfox request stages out of order');
    }

    public function test_wrong_route_and_unauthorized_reflection_are_rejected(): void
    {
        $route = $this->packet();
        $route['runs']['nuclei-authorized']['records'][0]['path'] = '/another';
        $this->rejects($route, 'wrong owned route');

        $raw = $this->packet();
        $record = $raw['runs']['dalfox-unauthorized']['records'][1];
        $record['kind'] = 'response';
        $record['status'] = 200;
        $record['owner'] = 'attack-xss-escalation';
        $record['headers'] = $this->escalationHeaders();
        $record['body'] = $record['query_value'];
        $raw['runs']['dalfox-unauthorized']['records'][1] = $record;
        $this->rejects($raw, 'unauthorized gated owner served');
    }

    public function test_wrong_or_removed_escalation_header_is_rejected(): void
    {
        $wrong = $this->packet();
        $wrong['runs']['dalfox-authorized']['records'][1]['headers']['Content-Security-Policy'] = "default-src 'self'";
        $this->rejects($wrong, 'missing/wrong escalation header');

        $removed = $this->packet();
        unset($removed['runs']['nuclei-authorized']['records'][0]['headers']['Content-Security-Policy']);
        $this->rejects($removed, 'missing/wrong escalation header');
    }

    public function test_malformed_and_empty_scanner_output_are_rejected(): void
    {
        $malformed = $this->packet();
        $malformed['runs']['dalfox-authorized']['scanner_output'] = ['not' => 'a report'];
        $this->rejects($malformed, 'dalfox output keys mismatch');

        $empty = $this->packet();
        $empty['runs']['nuclei-authorized']['scanner_output'] = [];
        $this->rejects($empty, 'nuclei produced no pinned finding');
    }

    public function test_scanner_hard_errors_and_stale_versions_are_rejected(): void
    {
        $hard = $this->packet();
        $hard['runs']['dalfox-authorized']['exit_status'] = 2;
        $this->rejects($hard, 'dalfox findings exit mismatch');

        $stale = $this->packet();
        $stale['runs']['nuclei-authorized']['scanner_version'] = '3.11.0';
        $this->rejects($stale, 'stale scanner version');
    }

    public function test_timeout_request_overflow_and_output_truncation_are_rejected(): void
    {
        $timeout = $this->packet();
        $timeout['runs']['nuclei-authorized']['elapsed_seconds'] = 91;
        $this->rejects($timeout, 'scanner timeout');

        $overflow = $this->packet();
        $overflow['runs']['nuclei-authorized']['request_count'] = 513;
        $this->rejects($overflow, 'request overflow');

        $truncated = $this->packet();
        $truncated['runs']['nuclei-authorized']['output_truncated'] = true;
        $this->rejects($truncated, 'scanner output truncated');
    }

    public function test_missing_spoofed_and_impossible_response_owners_are_rejected(): void
    {
        $missing = $this->packet();
        unset($missing['runs']['nuclei-authorized']['records'][0]['owner']);
        $this->rejects($missing, 'response record keys mismatch');

        $spoofed = $this->packet();
        $spoofed['runs']['nuclei-authorized']['records'][0]['owner'] = 'scanner-says-escalation';
        $this->rejects($spoofed, 'unknown response owner');

        $impossible = $this->packet();
        $impossible['runs']['nuclei-authorized']['records'][0]['owner'] = 'attack-xss-baseline';
        $this->rejects($impossible, 'baseline owner/payload mismatch');
    }

    public function test_explicit_null_and_router_rejection_are_not_missing_owner_records(): void
    {
        $packet = $this->packet();
        $packet['runs']['nuclei-unauthorized']['records'][] = [
            'kind' => 'router-reject', 'sequence' => 2, 'method' => 'GET',
            'path' => '/off-path', 'query' => 'q=x',
        ];
        $packet['runs']['nuclei-unauthorized']['request_count'] = 2;
        $packet['runs']['nuclei-unauthorized']['scanner_trace'][] = [
            'template' => '/opt/reflector/template/reflected-xss.yaml',
            'type' => 'http', 'input' => 'http://127.0.0.1:8898/off-path?q=x',
            'address' => '127.0.0.1:8898', 'error' => 'none',
        ];
        ReceiptVerifier::verifyPacket($this->withInclusiveTotal($packet), $this->pins);
        self::addToAssertionCount(1);

        $bad = $packet;
        $bad['runs']['nuclei-unauthorized']['records'][1]['owner'] = null;
        $this->rejects($bad, 'router-reject record keys mismatch');
    }

    public function test_dalfox_head_preflight_is_an_explicit_method_rejection(): void
    {
        $packet = $this->packet();
        array_unshift(
            $packet['runs']['dalfox-authorized']['records'],
            [
                'kind' => 'router-reject', 'sequence' => 1, 'method' => 'HEAD',
                'path' => ReceiptVerifier::PATH, 'query' => 'q=probe',
            ],
            $this->response(2, 'probe', 'attack-xss-baseline', 'page probe', ['Content-Type' => 'text/html; charset=utf-8'])
        );
        foreach ($packet['runs']['dalfox-authorized']['records'] as $index => &$record) {
            $record['sequence'] = $index + 1;
        }
        unset($record);
        $packet['runs']['dalfox-authorized']['request_count'] += 2;
        ReceiptVerifier::verifyPacket($this->withInclusiveTotal($packet), $this->pins);

        $wrong = $packet;
        $wrong['runs']['dalfox-authorized']['records'][0]['method'] = 'GET';
        $this->rejects($wrong, 'owned GET mislabeled router reject');
    }

    public function test_legacy_tag_correlates_only_its_real_matched_substring(): void
    {
        $packet = $this->packet();
        $legacy = $packet['runs']['dalfox-authorized']['records'][2];
        self::assertStringStartsWith("'\">", $legacy['query_value']);
        self::assertStringNotContainsString("'\">", $legacy['body']);
        self::assertStringContainsString('<IMG src=x class=dlx0123abcd>', $legacy['body']);
        ReceiptVerifier::verifyPacket($packet, $this->pins);
    }

    public function test_invocation_and_pin_drift_are_rejected(): void
    {
        $args = $this->packet();
        $args['runs']['nuclei-authorized']['invocation'][] = '-headless';
        $this->rejects($args, 'scanner invocation drift');

        $template = $this->packet();
        $template['template_sha256'] = str_repeat('0', 64);
        $this->rejects($template, 'stale template pin');
    }

    public function test_missing_or_malformed_nuclei_evidence_cannot_look_clean(): void
    {
        $missingOutput = $this->packet();
        $missingOutput['runs']['nuclei-unauthorized']['scanner_output'] = [['malformed_jsonl' => true]];
        $this->rejects($missingOutput, 'unauthorized nuclei output not empty');

        $missingTrace = $this->packet();
        $missingTrace['runs']['nuclei-unauthorized']['scanner_trace'] = [];
        $this->rejects($missingTrace, 'nuclei trace missing');

        $traceError = $this->packet();
        $traceError['runs']['nuclei-unauthorized']['scanner_trace'][0]['error'] = 'connection reset';
        $this->rejects($traceError, 'nuclei trace contains request error');

        $escaped = $this->packet();
        $escaped['runs']['nuclei-unauthorized']['scanner_trace'][0]['address'] = 'example.invalid:80';
        $this->rejects($escaped, 'nuclei trace escaped loopback target');

        $missingErrors = $this->packet();
        $missingErrors['runs']['nuclei-unauthorized']['scanner_error_log_present'] = false;
        $this->rejects($missingErrors, 'nuclei error log missing');
    }

    public function test_dalfox_final_fields_and_responder_correlation_are_required(): void
    {
        $missing = $this->packet();
        unset($missing['runs']['dalfox-authorized']['scanner_output']['findings'][0]['confidence']);
        $this->rejects($missing, 'dalfox confidence missing');

        $uncorrelated = $this->packet();
        $uncorrelated['runs']['dalfox-authorized']['scanner_output']['findings'][0]['response'] = 'HTTP/1.1 200 OK';
        $this->rejects($uncorrelated, 'dalfox finding response lacks marker');

        $empty = $this->packet();
        $empty['runs']['dalfox-authorized']['scanner_output']['findings'] = [];
        $empty['runs']['dalfox-authorized']['scanner_output']['meta']['findings_count'] = 0;
        $empty['runs']['dalfox-authorized']['scanner_output']['meta']['target_summary'][0]['findings_count'] = 0;
        $empty['runs']['dalfox-authorized']['scanner_output']['meta']['target_summary'][0]['status'] = 'clean';
        $empty['runs']['dalfox-authorized']['exit_status'] = 0;
        $this->rejects($empty, 'dalfox produced no final R/V evidence');
    }

    public function test_total_evidence_count_includes_the_receipt_itself(): void
    {
        $packet = $this->packet();
        $encoded = json_encode($packet, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        self::assertIsString($encoded);
        self::assertSame($packet['source_output_bytes'] + strlen($encoded) + 1, $packet['total_output_bytes']);

        $packet['total_output_bytes']--;
        $this->rejects($packet, 'receipt-inclusive output byte count mismatch');
    }

    public function test_actual_evidence_file_parsers_fail_closed_at_file_boundaries(): void
    {
        $directory = sys_get_temp_dir() . '/fp0338-evidence-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($directory, 0700));
        try {
            self::assertSame([['malformed_jsonl' => true]], EvidenceFiles::jsonLines($directory . '/missing.jsonl'));
            self::assertSame(8, file_put_contents($directory . '/partial.jsonl', "{\"ok\":1}"));
            self::assertSame([['ok' => 1]], EvidenceFiles::jsonLines($directory . '/partial.jsonl'));
            self::assertSame(6, file_put_contents($directory . '/partial.jsonl', '{"ok":'));
            self::assertSame([['malformed_jsonl' => true]], EvidenceFiles::jsonLines($directory . '/partial.jsonl'));

            self::assertSame(16, file_put_contents($directory . '/trace.log', '{"ok":1}{"ok":2}'));
            self::assertSame([['ok' => 1], ['ok' => 2]], EvidenceFiles::jsonSequence($directory . '/trace.log'));
            self::assertSame(7, file_put_contents($directory . '/trace.log', '{"ok":1'));
            self::assertSame([['malformed_trace' => true]], EvidenceFiles::jsonSequence($directory . '/trace.log'));
            self::assertSame(13, EvidenceFiles::evidenceBytes($directory));
        } finally {
            foreach (new \DirectoryIterator($directory) as $file) {
                if (!$file->isDot() && $file->isFile()) {
                    unlink($file->getPathname());
                }
            }
            rmdir($directory);
        }
    }

    public function test_router_evidence_fields_reject_instead_of_truncate_at_boundaries(): void
    {
        self::assertSame(str_repeat('x', 4096), EvidenceFiles::boundedRequestField(str_repeat('x', 4096), 4096, 'path'));
        try {
            EvidenceFiles::boundedRequestField(str_repeat('x', 4097), 4096, 'path');
            self::fail('overlong request evidence was accepted');
        } catch (InvalidArgumentException $error) {
            self::assertSame('path exceeds evidence boundary', $error->getMessage());
        }

        $router = (string) file_get_contents(__DIR__ . '/acceptance/reflector/router.php');
        self::assertStringContainsString("'/evidence-overflow'", $router);
        self::assertStringContainsString('EvidenceFiles::boundedRequestField($path, 4096', $router);
        self::assertStringContainsString('EvidenceFiles::boundedRequestField($query, 4096', $router);
    }

    public function test_readme_configuration_is_php73_safe_and_authorization_is_request_bound(): void
    {
        $make = static function (bool $trusted): Honeypot {
            $edgeAttestsDeceptionOrigin = static function (RequestContext $request) use ($trusted): bool {
                return $trusted && $request->path === ReceiptVerifier::PATH;
            };
            $config = new Config('respond');
            $config->gate = static function (RequestContext $request): bool { return true; };
            $config->attackEmulation = true;
            $config->isolatedOrigin = true;
            $config->reflectorAuthorizer = static function (RequestContext $request, string $class) use ($edgeAttestsDeceptionOrigin): bool {
                return $edgeAttestsDeceptionOrigin($request);
            };

            return Honeypot::default($config);
        };

        $request = new RequestContext('GET', ReceiptVerifier::PATH, 'q=' . rawurlencode("'\"><12345>"));
        self::assertNotNull($make(true)->respond($request));
        self::assertNull($make(false)->respond($request));

        $readme = file_get_contents(dirname(__DIR__) . '/README.md');
        self::assertIsString($readme);
        self::assertStringContainsString('$config = new Config(\'respond\');', $readme);
        $start = strpos($readme, '### Embedded vs. isolated origin');
        $end = strpos($readme, '### Parameter reactions', $start);
        self::assertIsInt($start);
        self::assertIsInt($end);
        $reflectorExamples = substr($readme, $start, $end - $start);
        self::assertStringNotContainsString('reflectorAuthorizer:', $reflectorExamples);
        self::assertGreaterThanOrEqual(2, substr_count($reflectorExamples, '$config->reflectorAuthorizer'));
    }

    public function test_xss_subtraction_keeps_other_authorized_classes_enabled(): void
    {
        $config = new Config('respond');
        $config->gate = static function (RequestContext $request): bool { return true; };
        $config->attackEmulation = true;
        $config->isolatedOrigin = true;
        $config->reflectClasses = ['xss' => false];
        $config->reflectorAuthorizer = static function (RequestContext $request, string $class): bool { return true; };
        $honeypot = Honeypot::default($config);

        self::assertNull($honeypot->respond(new RequestContext('GET', ReceiptVerifier::PATH, 'q=' . rawurlencode("'\"><12345>"))));
        $redirect = $honeypot->respond(new RequestContext('GET', '/go', 'url=https://evil.example/path'));
        self::assertNotNull($redirect);
        self::assertSame(302, $redirect->status);
    }

    public function test_actual_full_core_preserves_baseline_legacy_and_escalation_ownership(): void
    {
        $authorized = new Config('respond');
        $authorized->gate = static function (RequestContext $request): bool { return true; };
        $authorized->attackEmulation = true;
        $authorized->isolatedOrigin = true;
        $authorized->reflectorAuthorizer = static function (RequestContext $request, string $class): bool { return true; };
        $open = Honeypot::default($authorized);

        $closedConfig = clone $authorized;
        $closedConfig->reflectorAuthorizer = null;
        $closed = Honeypot::default($closedConfig);

        $marker = 'dlx0123abcddlxmid89abcdefxld4567cdef';
        $special = 'dlx0123abcd' . ReceiptVerifier::DALFOX_SPECIALS . 'xld4567cdef';
        $legacy = "'\"><IMG src=x onerror=alert(1) ClAss=dlx0123abcd>";
        $numeric = "'\"><12345>";
        foreach ([$marker, $special, $legacy, $numeric] as $value) {
            $request = new RequestContext('GET', ReceiptVerifier::PATH, 'q=' . rawurlencode($value));
            $response = $open->respond($request);
            self::assertNotNull($response);
            if ($value === $marker) {
                self::assertSame('attack-xss-baseline', $response->servedBy->ruleId);
                self::assertStringContainsString($marker, $response->body);
                self::assertArrayNotHasKey('Content-Security-Policy', $response->headers);
                self::assertNotNull($closed->respond($request));
            } elseif ($value === $legacy) {
                self::assertSame('attack-xss', $response->servedBy->ruleId);
                self::assertStringContainsString('<IMG src=x onerror=alert(1) ClAss=dlx0123abcd>', $response->body);
                self::assertStringNotContainsString("'\">", $response->body);
                self::assertArrayNotHasKey('Content-Security-Policy', $response->headers);
                self::assertNull($closed->respond($request));
            } else {
                self::assertSame('attack-xss-escalation', $response->servedBy->ruleId);
                self::assertStringContainsString($value, $response->body);
                foreach ($this->escalationHeaders() as $name => $expected) {
                    self::assertSame($expected, $response->headers[$name] ?? null, $name);
                }
                self::assertNull($closed->respond($request));
            }
        }
    }

    public function test_manual_workflow_and_runner_keep_the_execution_envelope_closed(): void
    {
        $root = dirname(__DIR__);
        $runner = (string) file_get_contents($root . '/tests/acceptance/reflector/run-reflect.sh');
        $execute = (string) file_get_contents($root . '/tests/acceptance/reflector/execute.sh');
        $dockerfile = (string) file_get_contents($root . '/tests/acceptance/reflector/Dockerfile');
        $workflow = (string) file_get_contents($root . '/.github/workflows/reflector-acceptance.yml');
        $all = $runner . "\n" . $execute . "\n" . $dockerfile;

        self::assertStringContainsString('workflow_dispatch:', $workflow);
        self::assertStringNotContainsString('pull_request:', $workflow);
        self::assertStringNotContainsString('push:', $workflow);
        self::assertStringContainsString('permissions:' . "\n" . '  contents: read', $workflow);
        self::assertStringContainsString('--network none', $runner);
        self::assertStringContainsString('--read-only', $runner);
        self::assertStringContainsString('--cap-drop ALL', $runner);
        self::assertStringContainsString('--security-opt no-new-privileges', $runner);
        self::assertStringContainsString('--pids-limit 128', $runner);
        self::assertStringContainsString('timeout --signal=TERM --kill-after=3 90', $execute);
        self::assertStringContainsString('ulimit -f 512', $execute);
        $collector = (string) file_get_contents($root . '/tests/acceptance/reflector/collect.php');
        self::assertStringContainsString('source_output_bytes', $collector);
        self::assertStringContainsString('strlen($encoded) + 1', $collector);
        $router = (string) file_get_contents($root . '/tests/acceptance/reflector/router.php');
        self::assertStringContainsString("require __DIR__ . '/autoload.php';", $router);
        self::assertStringNotContainsString('/vendor/autoload.php', $router);
        self::assertStringContainsString('REFLECT_REQUEST_LIMIT = 512', $router);
        self::assertStringContainsString('http://127.0.0.1:8898/products/quick-search?q=probe', $all);
        self::assertStringContainsString('php@sha256:172e13bc72d4fe6503db39b3ecad301406492ae661e1803138fa45eafc7491f2', $dockerfile);
        self::assertStringContainsString('EvidenceFiles.php /opt/reflector/EvidenceFiles.php', $dockerfile);
        foreach (['0.0.0.0', 'host.docker.internal', '--network host', '/var/run/docker.sock', '--privileged', '--publish'] as $forbidden) {
            self::assertStringNotContainsString($forbidden, $all);
        }
    }

    /** @param array<string,mixed> $packet */
    private function rejects(array $packet, string $message): void
    {
        try {
            ReceiptVerifier::verifyPacket($packet, $this->pins);
            self::fail('expected verifier rejection: ' . $message);
        } catch (InvalidArgumentException $e) {
            self::assertStringContainsString($message, $e->getMessage());
        }
    }

    /** @return array<string,mixed> */
    private function packet(): array
    {
        $runs = [
            'nuclei-authorized' => $this->fixtureRun('nuclei', 'authorized'),
            'nuclei-unauthorized' => $this->fixtureRun('nuclei', 'unauthorized'),
            'dalfox-authorized' => $this->fixtureRun('dalfox', 'authorized'),
            'dalfox-unauthorized' => $this->fixtureRun('dalfox', 'unauthorized'),
        ];

        return $this->withInclusiveTotal([
            'schema' => ReceiptVerifier::SCHEMA,
            'pins_sha256' => hash_file('sha256', __DIR__ . '/acceptance/reflector/versions.json'),
            'core_tree_sha256' => str_repeat('a', 64),
            'compiled_index_sha256' => str_repeat('b', 64),
            'attack_artifact_sha256' => str_repeat('c', 64),
            'template_sha256' => $this->pins['template']['sha256'],
            'started_at' => 1000,
            'ended_at' => 1100,
            'elapsed_seconds' => 100,
            'source_output_bytes' => array_sum(array_column($runs, 'output_bytes')),
            'total_output_bytes' => 0,
            'runs' => $runs,
        ]);
    }

    /** @return array<string,mixed> */
    private function fixtureRun(string $scanner, string $mode): array
    {
        $key = $scanner . '-' . $mode;
        $records = $this->records($scanner, $mode);
        $output = $scanner === 'nuclei' ? $this->nucleiOutput($mode) : $this->dalfoxOutput($mode);

        return [
            'mode' => $mode,
            'scanner' => $scanner,
            'scanner_version' => $this->pins[$scanner]['version'],
            'scanner_archive_sha256' => $this->pins[$scanner]['archive_sha256'],
            'core_tree_sha256' => str_repeat('a', 64),
            'compiled_index_sha256' => str_repeat('b', 64),
            'attack_artifact_sha256' => str_repeat('c', 64),
            'template_sha256' => $this->pins['template']['sha256'],
            'target' => ReceiptVerifier::TARGET,
            'invocation' => $this->invocation($scanner, $key),
            'started_at' => 1010,
            'ended_at' => 1020,
            'elapsed_seconds' => 10,
            'exit_status' => $scanner === 'dalfox' && count($output['findings']) > 0 ? 1 : 0,
            'timed_out' => false,
            'request_count' => count($records),
            'request_overflow' => false,
            'output_bytes' => 100,
            'output_truncated' => false,
            'errors' => [],
            'scanner_error_log_present' => $scanner === 'nuclei',
            'scanner_trace' => $scanner === 'nuclei' ? [[
                'template' => '/opt/reflector/template/reflected-xss.yaml',
                'type' => 'http',
                'input' => 'http://127.0.0.1:8898' . $records[0]['path'] . '?' . $records[0]['query'],
                'address' => '127.0.0.1:8898',
                'error' => 'none',
            ]] : [],
            'scanner_output' => $output,
            'records' => $records,
        ];
    }

    /** @return array<int,array<string,mixed>> */
    private function records(string $scanner, string $mode): array
    {
        $numeric = "probe'\"><12345>";
        if ($scanner === 'nuclei') {
            if ($mode === 'authorized') {
                return [$this->response(1, $numeric, 'attack-xss-escalation', 'page ' . $numeric, $this->escalationHeaders())];
            }

            return [$this->closed(1, $numeric)];
        }

        $marker = 'dlx0123abcddlxmid89abcdefxld4567cdef';
        $special = 'dlx0123abcd' . ReceiptVerifier::DALFOX_SPECIALS . 'xld4567cdef';
        $tag = "'\"><IMG src=x class=dlx0123abcd>";
        if ($mode === 'authorized') {
            return [
                $this->response(1, $marker, 'attack-xss-baseline', 'page ' . $marker, ['Content-Type' => 'text/html; charset=utf-8']),
                $this->response(2, $special, 'attack-xss-escalation', 'page ' . $special, $this->escalationHeaders()),
                $this->response(3, $tag, 'attack-xss', 'page <IMG src=x class=dlx0123abcd>', ['Content-Type' => 'text/html; charset=utf-8']),
            ];
        }

        return [
            $this->response(1, $marker, 'attack-xss-baseline', 'page ' . $marker, ['Content-Type' => 'text/html; charset=utf-8']),
            $this->closed(2, $special),
            $this->closed(3, $tag),
        ];
    }

    /** @param array<string,string> $headers @return array<string,mixed> */
    private function response(int $sequence, string $value, string $owner, string $body, array $headers): array
    {
        return [
            'kind' => 'response', 'sequence' => $sequence, 'method' => 'GET',
            'path' => ReceiptVerifier::PATH, 'query' => 'q=' . rawurlencode($value),
            'query_value' => $value, 'status' => 200, 'owner' => $owner,
            'headers' => $headers, 'body' => $body,
        ];
    }

    /** @return array<string,mixed> */
    private function closed(int $sequence, string $value): array
    {
        return [
            'kind' => 'core-null', 'sequence' => $sequence, 'method' => 'GET',
            'path' => ReceiptVerifier::PATH, 'query' => 'q=' . rawurlencode($value),
            'query_value' => $value,
        ];
    }

    /** @return array<string,string> */
    private function escalationHeaders(): array
    {
        return [
            'Content-Type' => 'text/html; charset=utf-8',
            'Content-Security-Policy' => "sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            'Cache-Control' => 'no-store',
            'Referrer-Policy' => 'no-referrer',
            'X-Content-Type-Options' => 'nosniff',
            'Cross-Origin-Resource-Policy' => 'same-origin',
            'Cross-Origin-Opener-Policy' => 'same-origin',
        ];
    }

    /** @return array<int,array<string,mixed>>|array<string,mixed> */
    private function nucleiOutput(string $mode): array
    {
        if ($mode !== 'authorized') {
            return [];
        }
        $payload = "'\"><12345>";

        return [[
            'template-id' => 'reflected-xss', 'type' => 'http', 'matcher-status' => true,
            'is_fuzzing_result' => true,
            'matched-at' => ReceiptVerifier::TARGET,
            'request' => 'GET /products/quick-search?q=probe' . rawurlencode($payload) . " HTTP/1.1\r\n\r\n",
            'response' => "HTTP/1.1 200 OK\r\n\r\npage " . $payload,
        ]];
    }

    /** @return array<string,mixed> */
    private function dalfoxOutput(string $mode): array
    {
        $findings = $mode === 'authorized' ? [[
            'type' => 'R', 'detection_method' => 'reflection', 'confidence' => 'low',
            'request' => 'GET /products/quick-search?q=%3CIMG+class%3Ddlx0123abcd%3E HTTP/1.1',
            'response' => 'HTTP/1.1 200 OK page <IMG class=dlx0123abcd>',
        ]] : [];

        return [
            'meta' => [
                'dalfox_version' => $this->pins['dalfox']['version'],
                'targets' => [ReceiptVerifier::TARGET],
                'findings_count' => count($findings),
                'incomplete' => false,
                'target_summary' => [[
                    'target' => ReceiptVerifier::TARGET,
                    'status' => count($findings) > 0 ? 'findings' : 'clean',
                    'findings_count' => count($findings),
                ]],
            ],
            'findings' => $findings,
        ];
    }

    /** @return string[] */
    private function invocation(string $scanner, string $key): array
    {
        $dir = '/output/' . $key;
        if ($scanner === 'nuclei') {
            return [
                '/opt/reflector/bin/nuclei', '-u', ReceiptVerifier::TARGET,
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
            '/opt/reflector/bin/dalfox', 'scan', ReceiptVerifier::TARGET,
            '--format', 'json', '--output', $dir . '/scanner.json', '--include-all',
            '--no-color', '--workers', '1', '--max-concurrent-targets', '1',
            '--max-targets-per-host', '1', '--skip-mining', '--skip-reflection-header',
            '--skip-reflection-cookie', '--skip-reflection-path', '--skip-ast-analysis',
            '--skip-waf-probe', '--waf-bypass', 'off', '--timeout', '5',
            '--scan-timeout', '60', '--retries', '0', '--max-payloads-per-param', '64',
        ];
    }

    /** @param array<string,mixed> $packet @return array<string,mixed> */
    private function withInclusiveTotal(array $packet): array
    {
        for ($attempt = 0; $attempt < 4; $attempt++) {
            $encoded = json_encode($packet, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            self::assertIsString($encoded);
            $total = $packet['source_output_bytes'] + strlen($encoded) + 1;
            if ($packet['total_output_bytes'] === $total) {
                return $packet;
            }
            $packet['total_output_bytes'] = $total;
        }

        return $packet;
    }
}
