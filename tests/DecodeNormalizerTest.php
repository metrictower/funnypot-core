<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Support\BoundedInspection;
use PHPUnit\Framework\TestCase;

/**
 * FP-0356 — the recursive decode/normalization stage folded onto the request surface before matching.
 * Proves each decoder EXPOSES an encoded payload (so the existing rules catch it) while retaining the
 * raw view, that benign encoded content is NOT decoded (bounded false positives), and that the fold is
 * bounded (no decode-bomb). decode_path is surfaced additively on the Verdict.
 */
final class DecodeNormalizerTest extends TestCase
{
    /**
     * @dataProvider evasions
     * Each encoded input, once folded, exposes the plaintext payload AND records the decoder — while
     * the RAW input does not contain the payload (the gate-bite: without the normalizer these miss).
     */
    public function test_fold_exposes_encoded_payload_and_records_decoder(string $raw, string $payload, string $decoder): void
    {
        $applied = [];
        $folded = BoundedInspection::foldLayers($raw, $applied);

        self::assertStringContainsStringIgnoringCase($payload, $folded, "fold must expose the payload for decoder {$decoder}");
        self::assertContains($decoder, $applied, "decode_path must record {$decoder}");
        // Retain-raw: the original bytes survive in the folded surface, so decoding never REMOVES a
        // match the raw would have caught.
        self::assertStringContainsString($raw, $folded, 'fold must retain the raw layer');
    }

    /** @return array<string,array{0:string,1:string,2:string}> raw => [raw, payload, decoder] */
    public static function evasions(): array
    {
        return [
            'plus'    => ['union+select+1', 'union select 1', 'plus'],
            'unicode' => ['\\u0075nion select', 'union select', 'unicode'],
            'entity'  => ['union&#x20;select', 'union select', 'entity'],
            'entity-named' => ['1&lt;script&gt;', '1<script>', 'entity'],
            'base64'  => ['x=' . base64_encode('union select 1 from users'), 'union select 1', 'base64'],
            'hex-prefixed' => ['\x75\x6e\x69\x6f\x6e select', 'union select', 'hex'],
            'hex-bare-long' => [bin2hex('union select all') . ' tail', 'union select all', 'hex'],
            'json'    => ['{"q":"union select 1"}', 'union select 1', 'json'],
        ];
    }

    /**
     * @dataProvider benign
     * Benign encoded content must NOT trigger its risky decoder — the false-positive guardrails.
     */
    public function test_benign_content_is_not_decoded(string $raw, string $decoderMustNotFire): void
    {
        $applied = [];
        BoundedInspection::foldLayers($raw, $applied);
        self::assertNotContains($decoderMustNotFire, $applied, "benign input must not fire {$decoderMustNotFire}: {$raw}");
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function benign(): array
    {
        return [
            // A 6-hex CSS colour has no \x/0x prefix and is under the bare-run floor — must NOT decode.
            'css colour' => ['background:#a1b2c3;color:#fff', 'hex'],
            // A long bare hex run that decodes to BINARY (a digest/hash) must be left alone.
            'hex digest' => [str_repeat('ab', 24), 'hex'],
            // A base64-shaped token that decodes to non-printable bytes (a binary blob / random id).
            'binary base64' => ['id=' . base64_encode(str_repeat("\x00\x01", 12)), 'base64'],
            // Not JSON at all — the json decoder must not fire on arbitrary text.
            'plain text' => ['the quick brown fox jumps over', 'json'],
        ];
    }

    public function test_fold_is_bounded_no_decode_bomb(): void
    {
        // Nested base64-of-base64 of a large blob: the fold must stay within the byte cap regardless
        // of decoder count (append() caps every layer; the loop stops at SUBJECT_BYTES).
        $inner = base64_encode(str_repeat('union select ', 4096));
        $nested = base64_encode($inner . $inner);
        $folded = BoundedInspection::foldLayers($nested);
        self::assertLessThanOrEqual(BoundedInspection::SUBJECT_BYTES, strlen($folded), 'fold must never exceed the byte cap');
    }

    public function test_surface_folds_query_and_body_but_not_path(): void
    {
        // query arm folds -> an entity-encoded payload in the query is exposed.
        $r = new RequestContext('GET', '/x', 'q=union&#x20;select');
        self::assertStringContainsStringIgnoringCase('union select', BoundedInspection::surface($r, 'query'));

        // body arm folds.
        $rb = new RequestContext('POST', '/x', '', [], 'union&#x20;select');
        self::assertStringContainsStringIgnoringCase('union select', BoundedInspection::surface($rb, 'body'));

        // path arm stays RAW (structural) — the entity is not decoded there.
        $rp = new RequestContext('GET', '/a&#x20;b', '');
        self::assertStringNotContainsString('a b', BoundedInspection::surface($rp, 'path'));
    }

    public function test_classify_records_decode_path_on_an_encoded_attack(): void
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool {
                return true;
            },
            'matched-only',
            null,
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            0,
            0,
            true // attackEmulation
        );
        $hp = Honeypot::default($config);

        // An HTML-entity-encoded SQLi payload: the raw bytes evade the sqli regex; the entity fold
        // exposes "union select" so the existing rule fires, and decode_path records 'entity'.
        $r = new RequestContext('POST', '/item', '', [], 'q=union&#x20;select&#x20;1');
        $verdict = $hp->classify($r, SiteProfile::empty());

        self::assertTrue($verdict->detection->matched, 'entity-encoded sqli must be caught via the fold');
        self::assertContains('entity', $verdict->decodePath, 'decode_path must record the entity decoder');
        self::assertArrayHasKey('decode_path', $verdict->toArray());
        self::assertContains('entity', $verdict->toArray()['decode_path']);
    }

    public function test_clean_request_has_empty_decode_path(): void
    {
        $config = new Config('respond', static function (RequestContext $r): bool {
            return true;
        }, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0, true);
        $hp = Honeypot::default($config);

        $verdict = $hp->classify(new RequestContext('GET', '/', ''), SiteProfile::empty());
        self::assertSame([], $verdict->decodePath, 'a clean request carries no decode_path');
    }
}
