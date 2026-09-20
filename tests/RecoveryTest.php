<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Classifier;
use Funnypot\Core\Compiler\LoadedTemplate;
use Funnypot\Core\Compiler\Matcher\RegexWitnessGenerator;
use Funnypot\Core\Compiler\TemplateLoader;
use Funnypot\Core\Detection;
use Funnypot\Core\Response\BundleValidator;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use PHPUnit\Framework\TestCase;

/**
 * Recovered coverage: typed-header regions (content_type / server / …), header-block
 * regex, and serving regex-witness (`rx`) and size (`sz`) bundles in respond mode.
 * Every synthesized case is re-checked with the same validator nuclei's matchers imply.
 */
final class RecoveryTest extends TestCase
{
    /** @var Classifier */
    private $classifier;

    /** @var ResponseSynthesizer */
    private $synth;

    protected function setUp(): void
    {
        $this->classifier = new Classifier();
        // No emulators → pure minimal synthesis (the guaranteed path).
        $this->synth = new ResponseSynthesizer(null);
    }

    /** @param array<string,mixed> $doc */
    private function load(array $doc): LoadedTemplate
    {
        $loader = new TemplateLoader();

        return $loader->fromArray($doc, json_encode($doc) ?: '', '/virtual/' . ($doc['id'] ?? 'x') . '.yaml');
    }

    /** @param array<string,mixed> $doc */
    private function classify(array $doc)
    {
        return $this->classifier->classify($this->load($doc));
    }

    // ---- typed-header classification ----

    public function test_word_content_type_is_in_and_pins_the_typed_header(): void
    {
        // Mirrors tyk-gateway-detect: body words + a content_type word, all under AND.
        $doc = [
            'id' => 'typed-ct',
            'info' => ['severity' => 'info', 'tags' => 'tech,detect'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/hello'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['Tyk GW', 'description'], 'condition' => 'and'],
                    ['type' => 'word', 'part' => 'content_type', 'words' => ['application/json']],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in, 'a content_type word matcher must no longer fold the template');
        self::assertArrayHasKey('Content-Type', $c->plan->typedHeader);
        self::assertContains('application/json', $c->plan->typedHeader['Content-Type']);
        // Mirrored into the header block so merge/validation see it as header-present.
        self::assertContains('application/json', $c->plan->headerWords);
    }

    public function test_word_server_typed_header_is_in(): void
    {
        // Mirrors openssl-detect: word(part:server) + status 200.
        $doc = [
            'id' => 'typed-server',
            'info' => ['severity' => 'info', 'tags' => 'tech'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'server', 'words' => ['OpenSSL']],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in);
        self::assertSame(['Server' => ['OpenSSL']], $c->plan->typedHeader);
    }

    public function test_dsl_contains_content_type_is_in(): void
    {
        $doc = [
            'id' => 'typed-dsl',
            'info' => ['severity' => 'info', 'tags' => 'tech'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/y'],
                'matchers' => [
                    ['type' => 'dsl', 'condition' => 'and', 'dsl' => [
                        "contains(content_type, 'text/xml')",
                        'status_code == 200',
                    ]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in);
        self::assertContains('text/xml', $c->plan->typedHeader['Content-Type'] ?? []);
        self::assertSame(200, $c->plan->status);
    }

    public function test_negative_typed_header_folds_the_and_template(): void
    {
        $doc = [
            'id' => 'typed-neg',
            'info' => ['severity' => 'info', 'tags' => 'tech'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/z'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'content_type', 'words' => ['text/html'], 'negative' => true],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        self::assertFalse($this->classify($doc)->in, 'a typed-header negative cannot be honoured → folds under AND');
    }

    // ---- typed-header synthesis ----

    public function test_synth_emits_content_type_value_and_validates(): void
    {
        $bundle = [
            's' => 200,
            'bw' => ['Tyk GW', 'description'],
            'hw' => ['application/json'],
            'th' => ['Content-Type' => ['application/json']],
            't' => ['typed-ct'],
        ];

        $resp = $this->synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp, 'a typed-header bundle must be servable');
        self::assertSame('application/json', $resp->headers['Content-Type']);
        self::assertStringContainsString('Tyk GW', $resp->body);
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    public function test_synth_emits_named_server_header(): void
    {
        $bundle = [
            's' => 200,
            'hw' => ['OpenSSL'],
            'th' => ['Server' => ['OpenSSL']],
            't' => ['typed-server'],
        ];

        $resp = $this->synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp);
        self::assertSame('OpenSSL', $resp->headers['Server']);
        // The nuclei per-header value match is satisfied: Server's value contains OpenSSL.
        self::assertStringContainsString('OpenSSL', $resp->headers['Server']);
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    // ---- regex-witness (rx) serving ----

    public function test_rx_witness_is_placed_in_the_body(): void
    {
        $bundle = [
            's' => 200,
            'rx' => ['aws_access_key_id = '],
            'nf' => ['<html', '<body'],
            't' => ['aws-credentials'],
        ];

        $resp = $this->synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp, 'an unanchored rx bundle is now servable');
        self::assertStringContainsString('aws_access_key_id = ', $resp->body);
        self::assertStringNotContainsStringIgnoringCase('<html', $resp->body);
    }

    public function test_anchored_rx_with_extra_body_is_skipped(): void
    {
        // Whole-body-exclusive (x) + a body word besides the witness cannot be guaranteed
        // offline (the anchor would break), so it is skipped rather than served wrong.
        $bundle = [
            's' => 200,
            'bw' => ['prefix'],
            'rx' => ['ONLY'],
            'x' => true,
            't' => ['anchored'],
        ];

        self::assertNull($this->synth->synthesize($bundle, Detection::none(), 'seed'));
        self::assertStringContainsString('anchored regex', $this->synth->lastSkipReason());
    }

    public function test_single_anchored_rx_is_served_as_the_witness(): void
    {
        $bundle = ['s' => 200, 'rx' => ['^only-this'], 'x' => true, 't' => ['a']];
        $resp = $this->synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp);
        self::assertSame('^only-this', $resp->body);
    }

    // ---- size (sz) serving ----

    public function test_sz_min_pads_the_body(): void
    {
        $bundle = ['s' => 200, 'bw' => ['hello'], 'sz' => ['min' => 100], 't' => ['sz-min']];
        $resp = $this->synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp);
        self::assertGreaterThanOrEqual(100, strlen($resp->body));
        self::assertStringContainsString('hello', $resp->body);
    }

    public function test_sz_exact_pads_to_the_target(): void
    {
        $bundle = ['s' => 200, 'bw' => ['abc'], 'sz' => ['eq' => 40], 't' => ['sz-eq']];
        $resp = $this->synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp);
        self::assertSame(40, strlen($resp->body));
        self::assertStringContainsString('abc', $resp->body);
    }

    public function test_sz_exact_shorter_than_required_is_skipped(): void
    {
        $bundle = ['s' => 200, 'bw' => ['this content is far too long for the exact size'], 'sz' => ['eq' => 5], 't' => ['sz-eq2']];
        self::assertNull($this->synth->synthesize($bundle, Detection::none(), 'seed'));
        self::assertStringContainsString('exact size', $this->synth->lastSkipReason());
    }

    public function test_sz_max_within_bound_is_served(): void
    {
        $bundle = ['s' => 200, 'bw' => ['ok'], 'sz' => ['max' => 50], 't' => ['sz-max']];
        $resp = $this->synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp);
        self::assertLessThanOrEqual(50, strlen($resp->body));
    }

    public function test_sz_padding_never_introduces_a_forbidden_substring(): void
    {
        // Forbidding every plausible filler but one still yields a valid padded body.
        $bundle = [
            's' => 200,
            'bw' => ['seed'],
            'nf' => [' ', '.', '-', '#', '/'],
            'sz' => ['min' => 60],
            't' => ['sz-fill'],
        ];
        $resp = $this->synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp);
        self::assertGreaterThanOrEqual(60, strlen($resp->body));
        foreach ([' ', '.', '-', '#', '/'] as $bad) {
            self::assertStringNotContainsString($bad, $resp->body);
        }
    }

    // ---- FP-0280: per-deploy witness menu selection + bounded canonical retry ----

    /** A synthesizer bound to a specific deploy identity, so witness selection is exercised. */
    private function synthFor(string $material): ResponseSynthesizer
    {
        return new ResponseSynthesizer(null, \Funnypot\Core\Response\Style::MINIMAL, null, null, PersonaIdentity::seedFromMaterial($material));
    }

    public function test_absent_rxm_serves_exactly_the_canonical(): void
    {
        $bundle = ['s' => 200, 'rx' => ['token=000'], 'nf' => [], 't' => ['a']];
        $resp = $this->synthFor('deploy-a')->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp);
        self::assertStringContainsString('token=000', $resp->body);
    }

    public function test_two_deploys_serve_different_valid_witnesses(): void
    {
        $rx = [];
        $rxm = [];
        foreach (['ka', 'kb', 'kc', 'kd', 'ke'] as $n) {
            $rx[] = $n . '=0';
            $rxm[] = [$n . '=1', $n . '=2', $n . '=3'];
        }
        $bundle = ['s' => 200, 'rx' => $rx, 'rxm' => $rxm, 't' => ['a']];

        $ra = $this->synthFor('deploy-a')->synthesize($bundle, Detection::none(), 'seed');
        $rb = $this->synthFor('deploy-b')->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($ra);
        self::assertNotNull($rb);
        self::assertNotSame($ra->body, $rb->body, 'different deploys select different witness vectors');
        foreach ([$ra->body, $rb->body] as $body) {
            foreach (explode("\n", $body) as $line) {
                self::assertSame(1, preg_match('/^k[a-e]=[0-9]$/', $line));
            }
        }
    }

    public function test_same_deploy_rescan_is_byte_identical(): void
    {
        $bundle = ['s' => 200, 'rx' => ['a0', 'b0'], 'rxm' => [['a1', 'a2'], ['b1', 'b2']], 't' => ['a']];
        $synth = $this->synthFor('deploy-a');
        $r1 = $synth->synthesize($bundle, Detection::none(), 'seed');
        $r2 = $synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($r1);
        self::assertNotNull($r2);
        self::assertSame($r1->body, $r2->body, 're-scan on one deploy is byte-identical');
    }

    public function test_whole_body_exclusive_serves_exactly_the_selected_witness(): void
    {
        // A single anchored witness with a menu: the served body is EXACTLY the deploy-selected witness.
        $bundle = ['s' => 200, 'rx' => ['foo0'], 'rxm' => [['foo1', 'foo2']], 'x' => true, 't' => ['a']];
        $synth = $this->synthFor('deploy-a');
        $resp = $synth->synthesize($bundle, Detection::none(), 'seed');
        self::assertNotNull($resp);
        self::assertContains($resp->body, ['foo0', 'foo1', 'foo2'], 'the exclusive body is one of the menu options');
        self::assertSame([$resp->body], $synth->lastRegexWitnesses(), 'the diagnostic reflects the served witness');
    }

    public function test_a_forbidden_alternate_retries_and_serves_the_canonical(): void
    {
        // A malformed bundle (alternate not filtered at freeze) whose alternate is a forbidden substring:
        // any deploy that selects it must retry ONCE with the canonical and serve that, never a miss.
        $bundle = ['s' => 200, 'rx' => ['ok'], 'rxm' => [['bad']], 'nf' => ['bad'], 't' => ['a']];
        for ($i = 0; $i < 32; $i++) {
            $synth = $this->synthFor('retry-' . $i);
            $resp = $synth->synthesize($bundle, Detection::none(), 'seed');
            self::assertNotNull($resp, "deploy {$i} must fall back to the canonical, never miss");
            self::assertSame('ok', $resp->body, 'the forbidden alternate is never served');
            self::assertSame(['ok'], $synth->lastRegexWitnesses(), 'the diagnostic records the canonical fallback');
        }
    }

    public function test_an_unsatisfiable_canonical_still_returns_null(): void
    {
        // Both the canonical and its alternate are forbidden substrings, so neither attempt can serve —
        // the bounded retry is a fallback, not a bypass.
        $bundle = ['s' => 200, 'rx' => ['xok'], 'rxm' => [['yok']], 'nf' => ['ok'], 't' => ['a']];
        for ($i = 0; $i < 8; $i++) {
            self::assertNull(
                $this->synthFor('none-' . $i)->synthesize($bundle, Detection::none(), 'seed'),
                "deploy {$i}: an unsatisfiable canonical must not be bypassed by an alternate"
            );
        }
    }

    // ---- header-block regex recovery ----

    public function test_unanchored_header_regex_becomes_a_header_word(): void
    {
        $gen = new RegexWitnessGenerator();
        $r = $gen->invert(['type' => 'regex', 'part' => 'header', 'regex' => ['PRTG']]);
        self::assertTrue($r->ok, 'an unanchored header-block regex is recoverable');
        self::assertNotEmpty($r->headerWords);
        self::assertEmpty($r->regexWitness, 'header witnesses are block words, not body witnesses');
    }

    public function test_anchored_header_regex_folds(): void
    {
        $gen = new RegexWitnessGenerator();
        $r = $gen->invert(['type' => 'regex', 'part' => 'header', 'regex' => ['^Server: nginx$']]);
        self::assertFalse($r->ok, 'an anchored header regex cannot be block-positioned safely');
    }

    public function test_typed_header_regex_folds(): void
    {
        $gen = new RegexWitnessGenerator();
        $r = $gen->invert(['type' => 'regex', 'part' => 'content_type', 'regex' => ['application/json']]);
        self::assertFalse($r->ok, 'typed-header regex is out of scope and must fold');
    }
}
