<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0544: the arithmetic/SSTI/cmdi payload oracles must fire on CORPUS-KEYED store-HIT paths
 * (/, /index.php, /search), not only on store-MISS paths. classifyContent resolves the store before
 * the linear scan, and the FP-0086 payload scan ran ONLY in the real-route M2 branch — so a param
 * injection to a crawled corpus key (what Tplmap/Commix/Caido hit) used to serve the static bundle and
 * miss the oracle. The fix runs the shared payloadVerdict() scan on the corpus-keyed branch too, placed
 * AFTER the owns_path block so the auth-success-witness CLEAN guard still wins, and gated identically
 * (classify on payloadInspection, serve on attackEmulation, reflector-gate the byte-echoing subset).
 */
final class CorpusKeyPayloadOracleTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(bool $payloadInspection = true, bool $attackEmulation = true): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, 'fixed');
        $cfg->attackEmulation = $attackEmulation;
        $cfg->payloadInspection = $payloadInspection;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function get(Honeypot $hp, string $path, string $query = ''): ?object
    {
        return $hp->respond(new RequestContext('GET', $path, $query, [], null, 'x.test'));
    }

    public function test_ssti_arithmetic_reflects_on_a_corpus_keyed_path(): void
    {
        // /index.php is a store HIT (corpus key with bundles) and not a declared real route, so it used
        // to serve its static bundle and never reach the SSTI numeric oracle.
        $r = $this->get($this->engine(), '/index.php', 'q=' . rawurlencode('{{1234*5678}}'));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('attack-ssti-numeric', $r->servedBy->ruleId ?? null);
        self::assertStringContainsString('7006652', (string) $r->body, '1234*5678 rendered');
    }

    public function test_homepage_payload_reflects_and_stays_content_type_coherent(): void
    {
        // The most visible corpus key. Security Invariant #5: the served oracle's Content-Type matches a
        // GET (text/html family), status app-chosen 200 — reflecting a payload on / must not emit a
        // mismatched type.
        $r = $this->get($this->engine(), '/', 'q=' . rawurlencode('{{1234*5678}}'));
        self::assertNotNull($r);
        self::assertSame('attack-ssti-numeric', $r->servedBy->ruleId ?? null);
        self::assertStringContainsString('7006652', (string) $r->body);
        self::assertStringStartsWith('text/html', strtolower((string) ($r->headers['Content-Type'] ?? '')));
    }

    public function test_benign_corpus_key_still_serves_its_static_bundle(): void
    {
        // Regression guard: no payload ⇒ matchPayload returns null ⇒ the static corpus bundle serves,
        // byte-for-byte as before. The oracle marker must be absent.
        $r = $this->get($this->engine(), '/index.php');
        self::assertNotNull($r);
        self::assertSame('GET /index.php', $r->servedBy->key ?? null, 'the static corpus bundle serves');
        self::assertStringNotContainsString('7006652', (string) $r->body);
    }

    public function test_payload_inspection_off_serves_the_static_bundle_not_the_oracle(): void
    {
        // Classification is gated on payloadInspection — with it off, the corpus key serves its static
        // bundle even under a payload (no new behaviour on a build that did not opt in).
        $r = $this->get($this->engine(false), '/index.php', 'q=' . rawurlencode('{{1234*5678}}'));
        self::assertNotNull($r);
        self::assertNotSame('attack-ssti-numeric', $r->servedBy->ruleId ?? null, 'no oracle without payloadInspection');
        self::assertStringNotContainsString('7006652', (string) $r->body);
    }

    public function test_classify_only_build_reaches_attack_but_serves_nothing_as_an_oracle(): void
    {
        // payloadInspection ON, attackEmulation OFF: classifyContent reaches the ATTACK_CLASS verdict, but
        // buildAttackFake does not serve the oracle — the serve path stays gated on attackEmulation.
        $hp = $this->engine(true, false);
        $r = $this->get($hp, '/index.php', 'q=' . rawurlencode('{{1234*5678}}'));
        if ($r !== null) {
            self::assertStringNotContainsString('7006652', (string) $r->body, 'no oracle served without attackEmulation');
        } else {
            self::assertNull($r);
        }
    }

    public function test_byte_echoing_oracle_on_a_corpus_key_is_reflector_gated(): void
    {
        // A reflects_input oracle (attack-xss) reached on a corpus key must stay behind serveReflector:
        // the default engine is NOT an isolated origin with an authorizer, so a full-tag payload must NOT
        // echo the attacker bytes — corpus keys gain no reflection surface a store-miss path lacks.
        $payload = '<script>alert(1)</script>';
        $r = $this->get($this->engine(), '/index.php', 'q=' . rawurlencode($payload));
        if ($r !== null) {
            self::assertStringNotContainsString($payload, (string) $r->body, 'raw attacker bytes must not be reflected on a non-isolated origin');
        } else {
            self::assertNull($r);
        }
    }

    public function test_insertion_is_after_the_auth_success_witness_guard(): void
    {
        // Source pin (plan-review F5): the Branch-B payload scan must sit AFTER the owns_path block's
        // auth-success-witness CLEAN early-return, so a payload to an owned login-success decoy can never
        // bypass that guard. A refactor that moves payloadVerdict above the guard reopens the hole.
        $src = file_get_contents(__DIR__ . '/../src/Honeypot.php');
        self::assertNotFalse($src);
        $guard = strpos($src, 'hasAuthSuccessWitness($bundles)');
        $branchB = strpos($src, 'FP-0544: a corpus-keyed store HIT');
        self::assertNotFalse($guard);
        self::assertNotFalse($branchB);
        self::assertLessThan($branchB, $guard, 'the auth-success-witness guard must precede the Branch-B payload scan');
    }

    public function test_both_branches_call_the_shared_payload_helper(): void
    {
        // No-drift pin: the real-route (Branch A) and corpus-key (Branch B) sites both route through the
        // single payloadVerdict() helper, so their verdict shape cannot diverge.
        $src = file_get_contents(__DIR__ . '/../src/Honeypot.php');
        self::assertNotFalse($src);
        self::assertSame(2, substr_count($src, '$this->payloadVerdict($r, $anomaly, $signals)'),
            'both Branch A and Branch B call payloadVerdict');
    }
}
