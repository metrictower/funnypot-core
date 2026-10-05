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

    /** A non-owned corpus key whose every bundle resolves to text/html (so the oracle may fire coherently). */
    private const HTML_KEY = '/Admin/frmWelcome.aspx';
    /** A non-owned corpus key with mixed/seed-variable bundles (serves non-HTML on some seeds). */
    private const MIXED_KEY = '/index.php';

    public function test_ssti_arithmetic_reflects_on_an_all_html_corpus_key(): void
    {
        // An all-bundles-HTML corpus key (bundlesServeHtml true) may fire the expr-eval oracle — it used to
        // serve its static bundle. The benign request and the payload request serve the SAME Content-Type
        // (text/html), so the oracle introduces no mismatch (Security Invariant #5).
        $benign = $this->get($this->engine(), self::HTML_KEY);
        $r = $this->get($this->engine(), self::HTML_KEY, 'q=' . rawurlencode('{{1234*5678}}'));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('attack-ssti-numeric', $r->servedBy->ruleId ?? null);
        self::assertStringContainsString('7006652', (string) $r->body, '1234*5678 rendered');
        // Invariant #5: benign CT == payload CT (both text/html) — the fix the review demanded.
        self::assertNotNull($benign);
        self::assertStringStartsWith('text/html', strtolower((string) ($benign->headers['Content-Type'] ?? '')));
        self::assertStringStartsWith('text/html', strtolower((string) ($r->headers['Content-Type'] ?? '')));
    }

    public function test_mixed_or_non_html_corpus_keys_do_not_serve_the_oracle(): void
    {
        // Security Invariant #5 (the fix for the FP-0544 review findings): the oracle fires ONLY when EVERY
        // bundle resolves to text/html. A MIXED key (/index.php — HTML on some seeds, text/plain on others)
        // and the extensionless non-HTML scanner-bait keys the reviewer flagged all serve their static
        // bundle, never the text/html oracle — so the served Content-Type can never mismatch, whichever
        // bundle the serve path seed-selects. (Owned paths serve injection rules via the pre-existing
        // owns_path/FP-0547 override, a separate code path not governed by this Branch-B gate.)
        foreach ([self::MIXED_KEY, '/search', '/(download)/etc/passwd', '/%c0', '/%00'] as $path) {
            $r = $this->get($this->engine(), $path, 'q=' . rawurlencode('{{1234*5678}}'));
            self::assertNotNull($r, $path);
            self::assertNotSame('attack-ssti-numeric', $r->servedBy->ruleId ?? null, "no text/html oracle on a non-all-HTML key: {$path}");
            self::assertStringNotContainsString('7006652', (string) $r->body, $path);
        }
    }

    public function test_benign_corpus_key_still_serves_its_static_bundle(): void
    {
        // Regression guard: no payload ⇒ matchPayload returns null ⇒ the static corpus bundle serves.
        $r = $this->get($this->engine(), self::HTML_KEY);
        self::assertNotNull($r);
        self::assertSame('GET ' . self::HTML_KEY, $r->servedBy->key ?? null, 'the static corpus bundle serves');
        self::assertStringNotContainsString('7006652', (string) $r->body);
    }

    public function test_payload_inspection_off_serves_the_static_bundle_not_the_oracle(): void
    {
        // Classification is gated on payloadInspection — with it off, an all-HTML corpus key serves its
        // static bundle even under a payload (no new behaviour on a build that did not opt in).
        $r = $this->get($this->engine(false), self::HTML_KEY, 'q=' . rawurlencode('{{1234*5678}}'));
        self::assertNotNull($r);
        self::assertNotSame('attack-ssti-numeric', $r->servedBy->ruleId ?? null, 'no oracle without payloadInspection');
        self::assertStringNotContainsString('7006652', (string) $r->body);
    }

    public function test_classify_only_build_reaches_attack_but_serves_nothing_as_an_oracle(): void
    {
        // payloadInspection ON, attackEmulation OFF: classifyContent reaches the ATTACK_CLASS verdict, but
        // buildAttackFake does not serve the oracle — the serve path stays gated on attackEmulation.
        $r = $this->get($this->engine(true, false), self::HTML_KEY, 'q=' . rawurlencode('{{1234*5678}}'));
        if ($r !== null) {
            self::assertStringNotContainsString('7006652', (string) $r->body, 'no oracle served without attackEmulation');
        } else {
            self::assertNull($r);
        }
    }

    public function test_non_expr_eval_payloads_on_an_html_corpus_key_serve_the_static_bundle(): void
    {
        // B-NARROW on an all-HTML key (so the HTML gate passes and Branch B runs): the scan runs ONLY the
        // expr-eval arithmetic/SSTI oracles. The broad payload-eligible rules that false-positive on benign
        // params of real-user corpus keys (XSS full tags, cmdi, sqli, SSO open-redirect, PHP array filters)
        // must NOT classify an attack here — they serve the static bundle. (Their genuine detection on
        // store-MISS paths and declared real routes is unchanged; this only scopes the corpus-key scan.)
        foreach ([
            'q=' . rawurlencode('<script>alert(1)</script>'),
            'q=' . rawurlencode(';id'),
            "q=' OR '1'='1",
            'redirect_uri=' . rawurlencode('//evil.test/'),
            'tags[]=books',
        ] as $query) {
            $r = $this->get($this->engine(), self::HTML_KEY, $query);
            self::assertNotNull($r, $query);
            self::assertSame('GET ' . self::HTML_KEY, $r->servedBy->key ?? null, "static bundle serves, not an attack: {$query}");
        }
    }

    public function test_branch_b_gated_on_all_bundles_html_content_type(): void
    {
        // Security Invariant #5 pin: the Branch-B oracle is gated on the entry resolving to text/html on
        // EVERY bundle (bundlesServeHtml mirrors ResponseSynthesizer's h→th→hw→text/plain precedence),
        // NOT a path-extension heuristic and NOT a single-bundle check. A mixed-CT entry (served CT is
        // seed-selected) is skipped, so the oracle's text/html can never mismatch the served bundle.
        $src = file_get_contents(__DIR__ . '/../src/Honeypot.php');
        self::assertNotFalse($src);
        self::assertStringContainsString('$this->bundlesServeHtml($bundles)', $src, 'Branch-B CT gate present');
        self::assertStringNotContainsString('js|mjs|css|json|map|svg', $src, 'the brittle extension heuristic is gone');
        // The gate iterates ALL bundles and bails on the first non-HTML (no bundles[0]-only shortcut).
        self::assertStringContainsString('foreach ($bundles as $bundle)', $src, 'gate checks every bundle');
    }

    public function test_expr_eval_reflecting_oracle_stays_reflector_gated_on_a_corpus_key(): void
    {
        // An expr-eval oracle that REFLECTS (attack-cmdi-arith, reflects_input) is still behind
        // serveReflector: on the default NON-isolated engine the computed result must never be echoed —
        // B-narrow adds no reflection surface a store-miss path lacks.
        $r = $this->get($this->engine(), self::HTML_KEY, 'q=' . rawurlencode('$((9471+2))'));
        if ($r !== null) {
            self::assertStringNotContainsString('9473', (string) $r->body, 'computed cmdi-arith result must not reflect on a non-isolated origin');
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
        self::assertSame(2, substr_count($src, '$this->payloadVerdict($r, $anomaly, $signals'),
            'both Branch A and Branch B call payloadVerdict (A full scan, B expr-eval-only)');
    }
}
