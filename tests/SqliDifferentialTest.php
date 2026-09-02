<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Attack\AttackBodies;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0227 — the behavioral / differential SQLi decoy (param route `param-sqli-differential`,
 * bucket `catalog`). A boolean-blind scanner (sqlmap --technique=B, Arachni, lonkero) confirms
 * SQLi by a three-request differential: a benign baseline P, a TRUE payload that must ≈ P, and a
 * FALSE payload that must materially ≠ P. This pins that directional relationship, plus the
 * numerical (`N-0`/`N-1`) and breaker/fixer (`'`/`''`) channels, determinism, and no-reflection.
 *
 * The decoy is a PARAM route, so it OWNS its baseline path: a benign `GET /catalog/x?id=1` renders
 * the same page P a TRUE probe does — which is the whole point (an attack-tier-only decoy would
 * 404 the benign baseline and fail the differential). Exercises matchParamRoute + renderRule
 * directly against the freshly compiled artifact — the tightest, gate-free path.
 */
final class SqliDifferentialTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-param.php';
    private const PATH = '/catalog/electronics';

    private function emulator(): TemplateAttackEmulator
    {
        /** @var array<string,mixed> $buckets */
        $buckets = require self::COMPILED;

        return new TemplateAttackEmulator([], [], null, null, $buckets);
    }

    /** Serve one query string against the decoy path; null if the param route did not match. */
    private function serve(string $query, int $seed = 0): ?SynthesizedResponse
    {
        return $this->serveOn(self::PATH, $query, $seed);
    }

    /**
     * Serve one request against an arbitrary catalog path + query; null if the param route did not
     * match. Used by the FP-0240 path-slug regression, which must key on the path segment.
     */
    private function serveOn(string $path, string $query, int $seed = 0): ?SynthesizedResponse
    {
        $emu = $this->emulator();
        $r = new RequestContext('GET', $path, $query, [], null);
        $match = $emu->matchParamRoute($r);
        if ($match === null) {
            return null;
        }

        return $emu->renderRule($match['rule'], $match['captures'], $seed, $r);
    }

    /** The benign baseline page P (seed 0). */
    private function baseline(): string
    {
        $p = $this->serve('id=10');
        self::assertNotNull($p, 'benign baseline must match the param route');
        self::assertSame(200, $p->status, 'benign baseline is a 200');

        return $p->body;
    }

    public function testBaselineIsServedForBenignRequest(): void
    {
        $p = $this->serve('id=10');
        self::assertNotNull($p);
        self::assertSame(200, $p->status);
        self::assertNotSame('', $p->body);
        self::assertArrayHasKey('Content-Type', $p->headers);
        self::assertStringContainsString('Product catalog', $p->body);
    }

    public function testNoQueryStillServesTheBaselinePage(): void
    {
        // A bare `GET /catalog/electronics` (no query) matches on path and falls to the default => P.
        $none = $this->serve('');
        self::assertNotNull($none);
        self::assertSame(200, $none->status);
        self::assertSame($this->baseline(), $none->body, 'no-query request must render the baseline P');
    }

    /**
     * Boolean TRUE must ≈ baseline. Byte-identical by construction (same authored body + same seed).
     * The randomized-constant variant proves the match is a PCRE backreference, not a literal 1=1.
     */
    public function testBooleanTrueEqualsBaseline(): void
    {
        $p = $this->baseline();
        self::assertSame($p, $this->serve('id=10 AND 1=1')->body, 'TRUE AND 1=1 must equal baseline');
        self::assertSame($p, $this->serve('id=10 AND 1234=1234')->body, 'randomized TRUE must equal baseline');
        // URL-encoded TRUE (%20 space, %3D `=`) — proves the in:request double-urldecode path resolves.
        self::assertSame($p, $this->serve('id=10%20AND%201%3D1')->body, 'URL-encoded TRUE must equal baseline');
        self::assertSame(200, $this->serve('id=10 AND 1=1')->status);
    }

    /** The acceptance-required quoted tautology `' OR '1'='1`, and the value-prefixed `1' OR '1'='1`. */
    public function testQuotedTautologyEqualsBaseline(): void
    {
        $p = $this->baseline();
        self::assertSame($p, $this->serve("id=' OR '1'='1")->body, "' OR '1'='1 must equal baseline");
        self::assertSame($p, $this->serve("id=1' OR '1'='1")->body, "1' OR '1'='1 must equal baseline");
    }

    /** Boolean FALSE must be materially different (empty result set): > 20% shorter, still 200. */
    public function testBooleanFalseDiffersFromBaseline(): void
    {
        $p = $this->baseline();
        $false = $this->serve('id=10 AND 1=2');
        self::assertNotNull($false);
        self::assertSame(200, $false->status, 'FALSE stays a 200 (a changed page, not an error)');
        self::assertNotSame($p, $false->body, 'FALSE must differ from baseline');
        self::assertLessThan(strlen($p) * 0.8, strlen($false->body), 'FALSE must be > 20% shorter than baseline');
        // Randomized FALSE constants must also read as FALSE.
        self::assertNotSame($p, $this->serve('id=10 AND 1234=5678')->body, 'randomized FALSE must differ from baseline');
    }

    /** Numerical channel: `id=10-0` (== baseline) vs `id=10-1` (changed). */
    public function testNumericalChannelSplitsLikeBoolean(): void
    {
        $p = $this->baseline();
        self::assertSame($p, $this->serve('id=10-0')->body, 'N-0 must equal baseline');
        self::assertSame($p, $this->serve('id=10+0')->body, 'N+0 must equal baseline');
        self::assertNotSame($p, $this->serve('id=10-1')->body, 'N-1 must differ from baseline');
        self::assertLessThan(strlen($p) * 0.8, strlen($this->serve('id=10-1')->body), 'N-1 must be materially shorter');

        // Discriminating N-0 (FP-0240 opus nit). A bare `id=10-0` reaches the baseline P via BOTH the
        // C2 arithmetic-identity alternative AND — if that alternative broke — the default fallthrough,
        // so `10-0 == P` alone doesn't actually prove the `[-+]0` channel fires. Prefix the identity to
        // a boolean-FALSE clause: TRUE-first case ordering means the C2 `[-+]\s*0\b` alternative must
        // claim `10-0` and serve P; remove that alternative and the payload falls to C3 and serves the
        // materially shorter empty page instead. So this assertion is sensitive to the identity channel.
        self::assertSame($p, $this->serve('id=10-0 AND 1=2')->body, 'arithmetic identity is TRUE even ahead of a FALSE clause (guards the [-+]0 channel)');
    }

    /**
     * FP-0240 — the numeric FALSE channel is anchored to the injected PARAM-VALUE context, not the
     * whole request surface. A benign digit-dash PATH slug must serve the baseline P (a scanner
     * crawling there gets a coherent baseline), while the same decrement in the `id=` value still
     * serves the empty page. Proves the channel moved off the path.
     */
    public function testNumericChannelDoesNotFireOnBenignPathSlug(): void
    {
        $p = $this->baseline();

        // Benign `\d-\d` slug with a plain param -> baseline P (200), NOT the empty page.
        $slug = $this->serveOn('/catalog/item-3-2', 'id=10');
        self::assertNotNull($slug, 'the digit-dash slug still matches the catalog param route');
        self::assertSame(200, $slug->status);
        self::assertSame($p, $slug->body, 'a benign \\d-\\d path slug must serve the baseline P, not the empty page');

        // Same slug, but the decrement is now in the param value -> empty page (channel unchanged).
        $inject = $this->serveOn('/catalog/item-3-2', 'id=10-1');
        self::assertNotNull($inject);
        self::assertSame(200, $inject->status);
        self::assertNotSame($p, $inject->body, '?id=10-1 must still serve the empty page even under a digit-dash slug');
        self::assertLessThan(strlen($p) * 0.8, strlen($inject->body), 'the injected decrement page stays materially shorter');
    }

    /** Breaker/fixer (Backslash-powered): a lone `'` breaks (500), a balanced `''` restores (200 == P). */
    public function testBreakerFixerChannel(): void
    {
        $p = $this->baseline();

        $breaker = $this->serve("id=10'");
        self::assertNotNull($breaker);
        self::assertSame(500, $breaker->status, "a lone quote id=10' must yield a 500 syntax error");
        self::assertNotSame($p, $breaker->body, 'the 500 body is not the baseline page');
        // FP-0279: the breaker mirrors 50-sqli via the same {{attack.sqli.*}} directives — the
        // exploit-confirmation markers must survive the per-deploy seeding at every deploy.
        self::assertStringContainsString('SQL syntax', $breaker->body, 'the breaker keeps the SQL syntax marker');
        self::assertStringContainsString(AttackBodies::MYSQL_1064, $breaker->body, 'the breaker keeps the full 1064 sentence');
        self::assertStringContainsString("' at line 1", $breaker->body, "the breaker keeps the ' at line 1 tail");

        $fixer = $this->serve("id=10''");
        self::assertNotNull($fixer);
        self::assertSame(200, $fixer->status, "a balanced quote id=10'' must restore a 200");
        self::assertSame($p, $fixer->body, "id=10'' must render the baseline page");

        // Encoded lone quote (%27) resolves through the double-urldecode surface to the same 500.
        self::assertSame(500, $this->serve('id=10%27')->status, 'encoded lone quote must also break');
    }

    /** The injected bytes are NEVER reflected into any served body (branch dispatches on structure). */
    public function testNeverReflectsAttackerBytes(): void
    {
        $canary = 'ZZMARKERZZ';
        foreach ([
            "id=10 AND '$canary'='$canary'",   // tautology carrying the canary       -> TRUE page P
            "id=10' AND $canary",               // lone-quote breaker carrying the canary -> 500
            "id=10 AND $canary=1",              // FALSE comparison carrying the canary -> empty page
        ] as $query) {
            $resp = $this->serve($query);
            self::assertNotNull($resp, "served for: $query");
            self::assertStringNotContainsString($canary, $resp->body, "must not reflect the canary for: $query");
            foreach ($resp->headers as $value) {
                self::assertStringNotContainsString($canary, $value, "must not reflect the canary in a header for: $query");
            }
        }
    }

    /** Deterministic per deploy: the same seed renders byte-identical bodies across calls. */
    public function testDeterministicAcrossCallsWithTheSameSeed(): void
    {
        self::assertSame($this->serve('id=10', 42)->body, $this->serve('id=10', 42)->body, 'same seed => identical body');
        self::assertSame(
            $this->serve('id=10 AND 1=1', 7)->body,
            $this->serve('id=10', 7)->body,
            'TRUE and baseline render identically under the same seed'
        );
    }

    /** The core regression invariant: TRUE == baseline AND FALSE != baseline, in one assertion pair. */
    public function testTrueEqualsBaselineAndFalseDiffersInvariant(): void
    {
        $p = $this->baseline();
        self::assertSame($p, $this->serve('id=10 AND 1=1')->body);
        self::assertNotSame($p, $this->serve('id=10 AND 1=2')->body);
    }
}
