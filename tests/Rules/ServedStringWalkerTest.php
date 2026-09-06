<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Rules;

use Funnypot\Core\Rules\ServedStringWalker;
use PHPUnit\Framework\TestCase;

/**
 * The shared served-string enumerator (FP-0262). It must scan every served leaf by default, skip
 * only matcher/identifier fields, handle both bundle shapes, scan header NAMES, and recognise a
 * capture-reflecting rule so the runtime egress guard can never become a reflected-byte oracle.
 */
final class ServedStringWalkerTest extends TestCase
{
    public function test_rule_leaves_scan_served_text_and_header_names(): void
    {
        $walker = new ServedStringWalker();
        $leaves = $walker->ruleLeaves([
            'id' => 'r',
            'response' => [
                'body' => 'SERVED-BODY',
                'headers' => ['X-Served' => 'HEADER-VALUE'],
            ],
        ], 'r');
        $values = array_values($leaves);
        self::assertContains('SERVED-BODY', $values);
        self::assertContains('HEADER-VALUE', $values);
        self::assertContains('X-Served', $values, 'header NAME must be scanned');
        // key-paths are readable.
        self::assertArrayHasKey('r.response.body', $leaves);
    }

    public function test_rule_leaves_skip_matcher_and_identifier_fields(): void
    {
        $walker = new ServedStringWalker();
        $leaves = array_values($walker->ruleLeaves([
            'id' => 'MATCH-ID',
            'tags' => ['MATCH-TAG'],
            'match' => [['in' => 'body', 'regex' => 'MATCH-REGEX', 'contains' => 'MATCH-WORD']],
            'when' => ['contains' => 'MATCH-WHEN'],
            'owns_path' => ['MATCH-PATH'],
            'lit' => 'MATCH-LIT',
            'lit_in' => 'body',
            'response' => ['body' => 'SERVED'],
        ], 'r'));
        self::assertContains('SERVED', $leaves);
        foreach (['MATCH-ID', 'MATCH-TAG', 'MATCH-REGEX', 'MATCH-WORD', 'MATCH-WHEN', 'MATCH-PATH', 'MATCH-LIT'] as $skipped) {
            self::assertNotContains($skipped, $leaves, "{$skipped} is a matcher/identifier field and must not be scanned");
        }
    }

    public function test_rule_leaves_skip_a_bin_body_but_keep_headers(): void
    {
        $walker = new ServedStringWalker();
        $leaves = array_values($walker->ruleLeaves([
            'id' => 'r', 'bin' => 1,
            'body' => 'QUJDRA==', // opaque base64 image bytes
            'headers' => ['Content-Type' => 'image/x-icon'],
        ], 'r'));
        self::assertNotContains('QUJDRA==', $leaves, 'a bin body is opaque bytes, not scanned');
        self::assertContains('image/x-icon', $leaves, 'a bin rule still serves its headers');
    }

    public function test_bundle_leaves_scan_bw_hw_rx_th_names_and_values_but_skip_forbidden_and_ids(): void
    {
        $walker = new ServedStringWalker();
        $leaves = array_values($walker->bundleLeaves([
            'bw' => ['BODY-WORD'],
            'hw' => ['HEADER-WORD'],
            'rx' => ['REGEX-WITNESS'],
            'th' => ['Location' => ['TYPED-VALUE']],
            'nf' => ['FORBIDDEN-BODY'],
            'hf' => ['FORBIDDEN-HEADER'],
            'pid' => 'PID-ID',
            't' => ['TEMPLATE-ID'],
            'sev' => 'high',
        ], 'b'));
        foreach (['BODY-WORD', 'HEADER-WORD', 'REGEX-WITNESS', 'TYPED-VALUE', 'Location'] as $served) {
            self::assertContains($served, $leaves, "{$served} is served and must be scanned");
        }
        foreach (['FORBIDDEN-BODY', 'FORBIDDEN-HEADER', 'PID-ID', 'TEMPLATE-ID'] as $notServed) {
            self::assertNotContains($notServed, $leaves, "{$notServed} is not served and must not be scanned");
        }
    }

    public function test_artifact_leaves_sniffs_the_nuclei_index_shape(): void
    {
        $walker = new ServedStringWalker();
        $leaves = array_values($walker->artifactLeaves([
            'schema' => 1,
            'manifest' => ['schema' => 1, 'source' => 'projectdiscovery/nuclei-templates'],
            'routes' => ['GET //interact.sh/en' => ['b' => [['bw' => ['SERVED']]]]],
            'templates' => ['t' => ['name' => 'honeypot-detect']],
        ], 'idx'));
        self::assertContains('SERVED', $leaves);
        // The route KEY, manifest and templates metadata are structural — never scanned.
        self::assertNotContains('projectdiscovery/nuclei-templates', $leaves);
        self::assertNotContains('honeypot-detect', $leaves);
        foreach ($leaves as $leaf) {
            self::assertStringNotContainsString('interact.sh', $leaf, 'a route KEY must never be scanned as a value');
        }
    }

    public function test_artifact_leaves_sniffs_the_flat_routes_index_shape(): void
    {
        $walker = new ServedStringWalker();
        $leaves = array_values($walker->artifactLeaves([
            'routes' => ['GET /x' => [['bw' => ['FLAT-SERVED'], 'th' => ['Location' => ['FLAT-TH']]]]],
            'templates' => [],
        ], 'flat'));
        self::assertContains('FLAT-SERVED', $leaves);
        self::assertContains('FLAT-TH', $leaves);
    }

    public function test_artifact_leaves_sniffs_the_param_bucket_shape(): void
    {
        $walker = new ServedStringWalker();
        $leaves = array_values($walker->artifactLeaves([
            'schema' => 1,
            'buckets' => ['seg' => [['id' => 'p', 'response' => ['body' => 'PARAM-SERVED']]]],
        ], 'param'));
        self::assertContains('PARAM-SERVED', $leaves);
    }

    public function test_reflects_captures_detects_reflectors_and_clears_non_reflectors(): void
    {
        self::assertTrue(ServedStringWalker::reflectsCaptures(['id' => 'a', 'reflects_input' => true]));
        self::assertTrue(ServedStringWalker::reflectsCaptures([
            'id' => 'b', 'response' => ['body' => 'echo {{match.0}} back'],
        ]));
        self::assertTrue(ServedStringWalker::reflectsCaptures([
            'id' => 'c', 'response' => ['body' => 'md5 {{compute.md5:match.1}}'],
        ]));
        self::assertFalse(ServedStringWalker::reflectsCaptures([
            'id' => 'd', 'response' => ['body' => 'a static {{persona.company.name}} page'],
        ]));
    }

    public function test_reflecting_inventory_matches_the_committed_attack_corpus(): void
    {
        // Assert the PREDICATE against the real corpus, not a hard-coded count — the count moves as
        // rules are added, but every reflecting rule must be recognised so the egress guard skips it.
        $attack = require dirname(__DIR__, 2) . '/resources/compiled/funnypot-attack.php';
        $reflecting = [];
        foreach ($attack as $rule) {
            if (is_array($rule) && ServedStringWalker::reflectsCaptures($rule)) {
                $reflecting[] = (string) ($rule['id'] ?? '?');
            }
        }
        // The known capture reflectors (xss / open-redirect / ssti / xmlrpc / ai-echo / phpcgi /
        // phpunit / ignition). At least these must be recognised.
        foreach (['attack-xss', 'attack-open-redirect', 'attack-ssti-numeric', 'attack-wp-xmlrpc'] as $id) {
            self::assertContains($id, $reflecting, "{$id} reflects captures and must be recognised");
        }
        // A non-reflecting decoy must NOT be treated as a reflector (else the egress guard skips it).
        self::assertNotContains('attack-wp-admin-redirect', $reflecting);
    }
}
