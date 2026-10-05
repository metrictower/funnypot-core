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

    /**
     * FP-0586: the decrement anchor must span the WHOLE value, so a benign value that merely STARTS with
     * a decrement-looking `N-M` but carries trailing text (a note, a dashed range) serves the baseline P,
     * not the empty page — while a bare injected `id=10-1` still serves P_empty.
     */
    public function testBenignDecrementLikeValueServesBaseline(): void
    {
        $p = $this->baseline();
        // Still FALSE on the bare injected decrement.
        self::assertNotSame($p, $this->serve('id=10-1')->body, 'bare id=10-1 still serves the empty page');
        // Benign values whose decrement-looking prefix is followed by text -> baseline P.
        self::assertSame($p, $this->serve('note=' . rawurlencode('10-2 off this week'))->body, 'a benign note with 10-2 off -> baseline');
        self::assertSame($p, $this->serve('label=' . rawurlencode('10-2 pack'))->body, 'a benign dashed label -> baseline');
        self::assertSame($p, $this->serve('q=' . rawurlencode('size 10-2 adapter'))->body, 'benign product text -> baseline');
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

    // ---- FP-0429: inequality / range / set operator differential (SafeComparison-routed) ----

    /**
     * Every TRUE inequality clause (`>`,`<`,`>=`,`<=`,`<>`,`!=`) must serve the baseline P byte-identically
     * — sqlmap's WAF-bypass vectors swap `1=1` for these, and the confirm test needs TRUE ≈ baseline.
     *
     * @dataProvider trueComparisons
     */
    public function testInequalityTrueEqualsBaseline(string $clause): void
    {
        $p = $this->baseline();
        $resp = $this->serve('id=10 AND ' . $clause);
        self::assertNotNull($resp, "served for TRUE clause: $clause");
        self::assertSame(200, $resp->status, "TRUE $clause stays 200");
        self::assertSame($p, $resp->body, "TRUE comparison '$clause' must be byte-identical to baseline P");
    }

    /** @return array<string,array{0:string}> */
    public function trueComparisons(): array
    {
        return [
            'gt' => ['2>1'], 'lt' => ['1<2'], 'ge-strict' => ['3>=1'], 'ge-eq' => ['2>=2'],
            'le-strict' => ['1<=3'], 'le-eq' => ['2<=2'], 'ne-anglebrackets' => ['3<>4'], 'ne-bang' => ['3!=4'],
            'arith-operand' => ['3*2>5'], 'encoded' => ['2%3E1'],
        ];
    }

    /** The logical prefix is `(?:and|or)` — an OR-prefixed comparison routes identically to an AND one. */
    public function testOrPrefixedComparisonRoutes(): void
    {
        $p = $this->baseline();
        $empty = $this->serve('id=10 AND 1=2')->body;
        self::assertSame($p, $this->serve('id=10 OR 2>1')->body, 'OR + TRUE comparison -> baseline P');
        self::assertSame($empty, $this->serve('id=10 OR 1>2')->body, 'OR + FALSE comparison -> P_empty');
    }

    /**
     * Every FALSE inequality clause must serve the P_empty page (byte-identical to the C3 `1=2` FALSE),
     * materially shorter than the baseline. Proves C5 reuses C3's empty response and the polarity flips.
     *
     * @dataProvider falseComparisons
     */
    public function testInequalityFalseEqualsEmptyPage(string $clause): void
    {
        $p = $this->baseline();
        $empty = $this->serve('id=10 AND 1=2')->body; // the canonical C3 FALSE page
        $resp = $this->serve('id=10 AND ' . $clause);
        self::assertNotNull($resp, "served for FALSE clause: $clause");
        self::assertSame(200, $resp->status, "FALSE $clause stays 200 (changed page, not an error)");
        self::assertNotSame($p, $resp->body, "FALSE comparison '$clause' must differ from baseline");
        self::assertSame($empty, $resp->body, "FALSE comparison '$clause' must render the same P_empty as C3");
        self::assertLessThan(strlen($p) * 0.8, strlen($resp->body), "FALSE $clause stays materially shorter");
    }

    /** @return array<string,array{0:string}> */
    public function falseComparisons(): array
    {
        return [
            'gt' => ['1>2'], 'lt' => ['2<1'], 'ge' => ['1>=2'], 'le' => ['3<=1'],
            'ne-eq-anglebrackets' => ['5<>5'], 'ne-eq-bang' => ['5!=5'], 'arith-operand' => ['2*2>9'],
        ];
    }

    /** Range (BETWEEN / NOT BETWEEN) and set (IN / NOT IN) clauses split TRUE->P / FALSE->P_empty. */
    public function testRangeAndSetDifferential(): void
    {
        $p = $this->baseline();
        $empty = $this->serve('id=10 AND 1=2')->body;

        // TRUE forms -> baseline P
        self::assertSame($p, $this->serve('id=10 AND 5 BETWEEN 1 AND 9')->body, 'in-range BETWEEN is TRUE');
        self::assertSame($p, $this->serve('id=10 AND 11 NOT BETWEEN 0 AND 9')->body, 'out-of-range NOT BETWEEN is TRUE');
        self::assertSame($p, $this->serve('id=10 AND 7 IN (6,7,8)')->body, 'member IN is TRUE');
        self::assertSame($p, $this->serve('id=10 AND 9 NOT IN (6,7,8)')->body, 'non-member NOT IN is TRUE');

        // FALSE forms -> P_empty
        self::assertSame($empty, $this->serve('id=10 AND 11 BETWEEN 0 AND 9')->body, 'out-of-range BETWEEN is FALSE');
        self::assertSame($empty, $this->serve('id=10 AND 5 NOT BETWEEN 1 AND 9')->body, 'in-range NOT BETWEEN is FALSE');
        self::assertSame($empty, $this->serve('id=10 AND 9 IN (6,7,8)')->body, 'non-member IN is FALSE');
        self::assertSame($empty, $this->serve('id=10 AND 7 NOT IN (6,7,8)')->body, 'member NOT IN is FALSE');
    }

    /**
     * INDETERMINATE contract: a function/column operand (the shape a data-extraction probe uses) is not a
     * static literal, so SafeComparison returns null, NO comparison case matches, and the decoy serves the
     * baseline P — never the FALSE page, never a 5xx. An extraction oracle gets a coherent, non-leaking page.
     */
    public function testIndeterminateComparisonServesBaseline(): void
    {
        $p = $this->baseline();
        foreach ([
            'id=10 AND ORD(MID(username,1,1))>65',
            'id=10 AND ASCII(SUBSTRING(password,1,1))<97',
            'id=10 AND LENGTH(database())>=4',
            'id=10 AND col BETWEEN 1 AND 9',
            'id=10 AND salary IN (100,200)',
        ] as $query) {
            $resp = $this->serve($query);
            self::assertNotNull($resp, "served for: $query");
            self::assertSame(200, $resp->status, "indeterminate clause must stay 200 (never 5xx): $query");
            self::assertSame($p, $resp->body, "indeterminate clause must serve baseline P: $query");
        }
    }

    /**
     * Boundary probe: a comparison clause that ALSO drags a stray quote (`id=10' AND 2>1`) must be served
     * its comparison page (here TRUE -> P, 200), NOT the lone-quote 500 breaker — the comparison pair is
     * ordered before C1 so the boolean channel wins over the string-break channel when both are present.
     * A truly lone quote with no comparison still breaks (guards that the shift didn't disable C1).
     */
    public function testQuotePlusComparisonTakesComparisonChannelNotBreaker(): void
    {
        $p = $this->baseline();
        $empty = $this->serve('id=10 AND 1=2')->body;

        $trueBoundary = $this->serve("id=10' AND 2>1");
        self::assertNotNull($trueBoundary);
        self::assertSame(200, $trueBoundary->status, "quote + TRUE comparison must serve 200, not the 500 breaker");
        self::assertSame($p, $trueBoundary->body, "quote + TRUE comparison must serve the baseline P");

        $falseBoundary = $this->serve("id=10' AND 1>2");
        self::assertNotNull($falseBoundary);
        self::assertSame(200, $falseBoundary->status, "quote + FALSE comparison stays a 200 changed page");
        self::assertSame($empty, $falseBoundary->body, "quote + FALSE comparison must serve P_empty");

        // A lone quote with NO comparison clause still breaks (C1 intact).
        self::assertSame(500, $this->serve("id=10'")->status, "a bare lone quote must still 500");
    }

    /**
     * FP-0429 review F1: a comparison clause terminated by a trailing SQL comment (`-- -`, `#`, a block
     * comment) or a trailing non-logical clause (`ORDER BY`) — the shape sqlmap/ghauri actually emit — must still
     * split TRUE->P / FALSE->P_empty. Without the SafeComparison comment-strip these all collapsed to
     * baseline P (zero differential -> scanner concludes "not injectable").
     */
    public function testCommentTerminatedComparisonDifferential(): void
    {
        $p = $this->baseline();
        $empty = $this->serve('id=10 AND 1=2')->body;

        // TRUE forms with a terminator -> P
        self::assertSame($p, $this->serve('id=10 AND 2>1-- -')->body, 'TRUE + line comment -> P');
        self::assertSame($p, $this->serve('id=10 AND 2>1 ORDER BY 1')->body, 'TRUE + trailing clause -> P');
        self::assertSame($p, $this->serve('id=10 AND 5 BETWEEN 1 AND 9-- -')->body, 'TRUE BETWEEN + comment -> P');

        // FALSE forms with a terminator -> P_empty
        self::assertSame($empty, $this->serve('id=10 AND 1>2-- -')->body, 'FALSE + line comment -> P_empty');
        self::assertSame($empty, $this->serve('id=10 AND 1>2#neutralise')->body, 'FALSE + hash comment -> P_empty');
        self::assertSame($empty, $this->serve('id=10 AND 11 BETWEEN 0 AND 9-- -')->body, 'FALSE BETWEEN + comment -> P_empty');
        self::assertSame($empty, $this->serve('id=10 AND 9 IN (6,7,8)-- -')->body, 'FALSE IN + comment -> P_empty');
        self::assertSame($empty, $this->serve('id=10 AND 1>2 ORDER BY 1')->body, 'FALSE + trailing clause -> P_empty');

        // FP-0585: a MySQL versioned conditional comment wrapping the comparison is unwrapped (live) and splits.
        self::assertSame($p, $this->serve('id=10 AND ' . rawurlencode('/*!50000 2>1*/'))->body, 'versioned-comment TRUE -> P');
        self::assertSame($empty, $this->serve('id=10 AND ' . rawurlencode('/*!50000 1>2*/'))->body, 'versioned-comment FALSE -> P_empty');

        // On-wire encoded forms (consistently percent/`+`-encoded) must split the same way through the fold.
        self::assertSame($p, $this->serve('id=10%20AND%202%3E1--%20-')->body, 'encoded TRUE + encoded comment -> P');
        self::assertSame($empty, $this->serve('id=10+AND+1%3E2--+-')->body, 'encoded FALSE + `+`-encoded comment -> P_empty');
        self::assertSame($empty, $this->serve('id=10+AND+9+IN+(6,7,8)--+')->body, 'encoded FALSE IN + comment -> P_empty');
    }

    /**
     * FP-0429 review F2: an INDETERMINATE comparison (function/column operand) that ALSO carries a lone
     * unbalanced quote at a token boundary is served the pre-existing C1 breaker 500 — the lone quote
     * breaks the (fake) string literal, which is a believable syntax error, NOT a tell. This is the
     * documented exception to "INDETERMINATE -> baseline P": the quote, not the comparison, decides it.
     * A quote-free indeterminate clause still serves the baseline P (covered above).
     */
    public function testIndeterminateWithLoneQuoteHitsTheC1Breaker(): void
    {
        $extraction = $this->serve("id=10' AND ORD(MID(username,1,1))>65");
        self::assertNotNull($extraction);
        self::assertSame(500, $extraction->status, "a lone quote + indeterminate extraction probe breaks via C1 (500), not baseline");
        self::assertStringContainsString('SQL syntax', $extraction->body, 'the breaker keeps its believable syntax-error marker');
    }

    /** Benign text carrying `and`/`or` but no comparison operator must serve the baseline P, never P_empty. */
    public function testBenignBooleanProseServesBaseline(): void
    {
        $p = $this->baseline();
        foreach ([
            'q=cats and dogs or small birds',
            'note=buy 2 apples and 3 oranges',
            'q=in stock and on sale',
        ] as $query) {
            $resp = $this->serve($query);
            self::assertNotNull($resp, "served for benign prose: $query");
            self::assertSame(200, $resp->status);
            self::assertSame($p, $resp->body, "benign and/or prose must serve baseline P: $query");
        }
    }

    /** Attacker bytes in a comparison clause are never reflected (TRUE, FALSE, and INDETERMINATE arms). */
    public function testComparisonNeverReflectsAttackerBytes(): void
    {
        $canary = 'ZZCMPZZ';
        foreach ([
            "id=10 AND 2>1&note=$canary",         // TRUE comparison, canary in a sibling param -> P
            "id=10 AND 1>2&note=$canary",         // FALSE comparison, canary in a sibling param -> P_empty
            "id=10 AND ORD($canary)>65",          // INDETERMINATE (function operand) -> baseline P
        ] as $query) {
            $resp = $this->serve($query);
            self::assertNotNull($resp, "served for: $query");
            self::assertStringNotContainsString($canary, $resp->body, "must not reflect the canary for: $query");
        }
    }
}
