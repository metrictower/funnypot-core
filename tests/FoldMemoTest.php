<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\BoundedInspection;
use PHPUnit\Framework\TestCase;

/**
 * FP-0549: BoundedInspection::surface()/surfaces() memoize the folded request/query/body surface per
 * RequestContext (perf-only). These tests pin that the memo is used, is byte-identical to the unmemoized
 * arm value (NOT the bare unguarded fold), preserves the rejected-target guard, and never lets the raw
 * (FP-0530) path poison the raw=false slot.
 */
final class FoldMemoTest extends TestCase
{
    /** A query/body that folds (percent-encoded markup) so folded != raw. */
    private const Q = 'q=%3Cscript%3Ealert(1)%3C%2Fscript%3E';
    private const B = 'x=%27%22%3E%3Cimg%20src%3Dx%3E';

    private function req(bool $admitted = true): RequestContext
    {
        return new RequestContext('GET', '/shop/widgets', self::Q, [], self::B, 'x.test', 'https', '', $admitted);
    }

    public function test_memo_populated_and_stable_across_calls(): void
    {
        foreach (['request', 'query', 'body'] as $arm) {
            $r = $this->req();
            $s1 = BoundedInspection::surface($r, $arm);
            $s2 = BoundedInspection::surface($r, $arm);
            self::assertSame($s1, $s2, "surface('{$arm}') stable");
            self::assertArrayHasKey($arm, $r->foldStrMemo, "surface('{$arm}') memo populated");
            self::assertSame($s1, $r->foldStrMemo[$arm], "surface('{$arm}') returns the memo");

            $l1 = BoundedInspection::surfaces($r, $arm);
            $l2 = BoundedInspection::surfaces($r, $arm);
            self::assertSame($l1, $l2, "surfaces('{$arm}') stable");
            self::assertArrayHasKey($arm, $r->foldListMemo, "surfaces('{$arm}') memo populated");
            self::assertSame($l1, $r->foldListMemo[$arm], "surfaces('{$arm}') returns the memo");
        }
    }

    public function test_memo_equals_unmemoized_arm_semantics(): void
    {
        // Byte-equality against the ARM value of a SECOND fresh request's FIRST (unmemoized) call — not
        // the bare unguarded fold (plan-review fix #2).
        foreach (['request', 'query', 'body'] as $arm) {
            $memoed = $this->req();
            BoundedInspection::surface($memoed, $arm);      // populate
            BoundedInspection::surfaces($memoed, $arm);

            $fresh = $this->req();
            self::assertSame(BoundedInspection::surface($fresh, $arm), $memoed->foldStrMemo[$arm], "surface('{$arm}') memo == arm semantics");
            self::assertSame(BoundedInspection::surfaces($fresh, $arm), $memoed->foldListMemo[$arm], "surfaces('{$arm}') memo == arm semantics");
        }
    }

    public function test_rejected_target_request_arm_memoizes_empty(): void
    {
        // plan-review fix #1: requestSubject() returns '' for a rejected target; the memo must preserve
        // that guard (a naive memo of foldLayers(requestRaw()) would wrongly return the folded surface).
        $r = $this->req(false);
        self::assertSame('', BoundedInspection::surface($r, 'request'), 'rejected target folds to empty string');
        self::assertSame('', $r->foldStrMemo['request']);
        self::assertSame([''], BoundedInspection::surfaces($r, 'request'), 'rejected target folds to a single empty-string layer');
        self::assertSame([''], $r->foldListMemo['request']);
    }

    public function test_raw_path_never_poisons_the_non_raw_slot(): void
    {
        // plan-review fix #3: raw=true returns the UNFOLDED surface and must not populate or poison the
        // raw=false memo slot; raw=false still returns the folded surface.
        foreach (['query', 'body'] as $arm) {
            $r = $this->req();
            $rawFirst = BoundedInspection::surface($r, $arm, [], true);
            self::assertArrayNotHasKey($arm, $r->foldStrMemo, "raw=true did not populate the '{$arm}' memo");
            $folded = BoundedInspection::surface($r, $arm, [], false);
            self::assertNotSame($rawFirst, $folded, "raw ('{$arm}') is the unfolded surface, folded differs");
            self::assertSame($folded, $r->foldStrMemo[$arm], "raw=false populated the memo with the FOLDED value");

            // The reverse order: folded first, then raw — raw must still return the unfolded surface.
            $r2 = $this->req();
            BoundedInspection::surface($r2, $arm, [], false);
            self::assertSame($rawFirst, BoundedInspection::surface($r2, $arm, [], true), "raw=true still unfolded after a raw=false call");
        }
    }

    public function test_decoded_markup_actually_folded(): void
    {
        // Sanity: the memoized folded value really contains the decoded markup (so the test exercises a
        // real fold, not a no-op where raw==folded).
        $r = $this->req();
        self::assertStringContainsString('<script>', BoundedInspection::surface($r, 'query'), 'query fold decodes %3Cscript%3E');
        self::assertStringNotContainsString('<script>', BoundedInspection::surface($r, 'query', [], true), 'raw query keeps %3C');
    }
}
