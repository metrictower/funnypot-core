<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\BoundedInspection;
use PHPUnit\Framework\TestCase;

/**
 * FP-0534: per-layer matching. foldLayerList() is the fold as an ordered list; surfaces() is the
 * per-selector layer list used by match-any evaluation. The core invariant is that joining the list
 * with a single space reproduces foldLayers() exactly (bar the documented dangling-space cap boundary),
 * so detection is preserved while a match can no longer straddle the layer joiner.
 */
final class FoldLayerListTest extends TestCase
{
    /** @return array<string,array{0:string}> */
    public function foldInputs(): array
    {
        $cases = [
            'plain'                 => 'nothing to decode here',
            'empty'                 => '',
            'plus'                  => 'q=a+b+c',
            'percent'               => '/path?x=%2Fetc%2Fpasswd',
            'double-percent'        => '%2561%2562',
            'base64'                => 'data=' . base64_encode('cat /etc/passwd'),
            'entity'                => 'x=&lt;script&gt;',
            'hex-prefixed'          => 'v=0x41420x4344',
            'unicode'               => 'u=\\u0041\\u0042',
            'json-nested'           => '{"a":"%2Fetc"}',
            'shell-ifs'             => 'cat${IFS}/etc/passwd',
            'mixed-chain'           => '/x?c=%25%37%42' . base64_encode('id'),
            'cap-saturating-raw'    => str_repeat('A', BoundedInspection::SUBJECT_BYTES + 500),
            'cap-saturating-plus'   => str_repeat('a+', BoundedInspection::SUBJECT_BYTES),
            'cap-saturating-pct'    => str_repeat('%41', BoundedInspection::SUBJECT_BYTES),
            // Exact SB-1 boundary with a firing decoder: the joiner space fits (used -> SB) but the
            // decoded layer clips to empty. foldLayers records the decoder and keeps a dangling space;
            // foldLayerList must record the same decoder (parity) while omitting the empty layer.
            'cap-boundary-sb-1-pct' => str_repeat('A', BoundedInspection::SUBJECT_BYTES - 4) . '%41',
        ];
        $out = [];
        foreach ($cases as $k => $v) {
            $out[$k] = [$v];
        }

        return $out;
    }

    /**
     * @dataProvider foldInputs
     */
    public function test_fold_list_joins_back_to_string(string $raw): void
    {
        $a = [];
        $b = [];
        $string = BoundedInspection::foldLayers($raw, $a);
        $list = BoundedInspection::foldLayerList($raw, $b);

        // Documented divergence: at the exact cap the legacy string can end in a dangling joiner space.
        self::assertSame(rtrim($string, ' '), rtrim(implode(' ', $list), ' '), 'join(list) must equal foldLayers');
        // decode_path parity: same applied-decoder set in the same order.
        self::assertSame($a, $b, 'applied-decoder bookkeeping must match foldLayers');
        self::assertNotEmpty($list, 'list is always non-empty (element 0 is the raw)');
    }

    public function test_layer_list_shape(): void
    {
        self::assertSame(['plain'], BoundedInspection::foldLayerList('plain'));
        self::assertSame(['a+b', 'a b'], BoundedInspection::foldLayerList('a+b'));
        // double-percent peels twice: %2561 -> %61 -> a
        self::assertSame(['%2561', '%61', 'a'], BoundedInspection::foldLayerList('%2561'));
    }

    public function test_surfaces_arms(): void
    {
        $r = new RequestContext('GET', '/search', 'q=a+b', [], null, 'x.test');

        // path is single-surface (never folded)
        self::assertSame(['/search'], BoundedInspection::surfaces($r, 'path'));
        // query non-raw folds to a layer list
        self::assertSame(['q=a+b', 'q=a b'], BoundedInspection::surfaces($r, 'query'));
        // query raw is the single unfolded surface (capture path, FP-0530)
        self::assertSame(['q=a+b'], BoundedInspection::surfaces($r, 'query', [], true));
        // fields has no single-string surface -> [''] (defensive, evalConditions routes fields elsewhere)
        self::assertSame([''], BoundedInspection::surfaces($r, 'fields'));
        self::assertSame(['GET'], BoundedInspection::surfaces($r, 'method'));
    }

    public function test_surfaces_request_rejected_target_is_empty_layer(): void
    {
        // A path over TARGET_BYTES makes targetAccepted() false -> request surface is [''].
        $big = '/' . str_repeat('a', BoundedInspection::TARGET_BYTES + 1);
        $r = new RequestContext('GET', $big, '', [], null, 'x.test');
        self::assertSame([''], BoundedInspection::surfaces($r, 'request'));
    }

    public function test_straddle_window_cannot_match_across_joiner(): void
    {
        // The raw/decoded boundary: raw 'a+b' folds to "a+b a b". A pattern needing a '+' adjacent to a
        // space ('b a') exists only in the joined string, never in a single layer -> no per-layer match.
        $list = BoundedInspection::foldLayerList('a+b');
        $joined = implode(' ', $list);
        self::assertSame(1, preg_match('~b a~', $joined), 'the straddle window exists in the joined string');
        $straddle = 0;
        foreach ($list as $layer) {
            $straddle += preg_match('~b a~', $layer);
        }
        self::assertSame(0, $straddle, 'no single layer contains the straddle window');
    }
}
