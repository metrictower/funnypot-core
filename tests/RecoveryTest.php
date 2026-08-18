<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Classifier;
use Funnypot\Compiler\LoadedTemplate;
use Funnypot\Compiler\Matcher\RegexWitnessGenerator;
use Funnypot\Compiler\TemplateLoader;
use Funnypot\Detection;
use Funnypot\Response\BundleValidator;
use Funnypot\Synthesis\ResponseSynthesizer;
use PHPUnit\Framework\TestCase;

/**
 * Recovered coverage: typed-header regions (content_type / server / …), header-block
 * regex, and serving regex-witness (`rx`) and size (`sz`) bundles in respond mode.
 * Every synthesized case is re-checked with the same validator nuclei's matchers imply.
 */
final class RecoveryTest extends TestCase
{
    private Classifier $classifier;
    private ResponseSynthesizer $synth;

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
