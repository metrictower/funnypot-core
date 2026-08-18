<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Bundle;
use Funnypot\Compiler\PersonaCap;
use PHPUnit\Framework\TestCase;

/**
 * keepScore ranking, the ≤N cap, the implausible-root drop, and the weight tiers —
 * exercised on hand-built bundles so the pass is provable without the full corpus.
 */
final class PersonaCapTest extends TestCase
{
    private PersonaCap $cap;

    protected function setUp(): void
    {
        $this->cap = new PersonaCap();
    }

    /**
     * @param string[] $ids
     */
    private function bundle(string $pid, int $status, string $sev, array $ids): Bundle
    {
        $b = new Bundle();
        $b->status = $status;
        $b->product = $pid;
        $b->severity = $sev;
        $b->templateIds = $ids;

        return $b;
    }

    /**
     * @param array<string,string[]> $tagsById
     * @return array<string,array{sev:string,tags:string[],name:string}>
     */
    private function meta(array $tagsById): array
    {
        $out = [];
        foreach ($tagsById as $id => $tags) {
            $out[$id] = ['sev' => 'info', 'tags' => $tags, 'name' => $id];
        }

        return $out;
    }

    public function test_prominent_product_outranks_obscure_and_meta(): void
    {
        $meta = $this->meta(['a' => ['tech'], 'b' => ['tech'], 'c' => ['tech']]);
        $core = $this->bundle('nginx', 200, 'info', ['a']);
        $obscure = $this->bundle('some-obscure-iot-box', 200, 'info', ['b']);
        $grabBag = $this->bundle('discovery', 200, 'info', ['c']); // META_PID

        $sCore = $this->cap->keepScore($core, $meta);
        $sObscure = $this->cap->keepScore($obscure, $meta);
        $sMeta = $this->cap->keepScore($grabBag, $meta);

        self::assertGreaterThan($sObscure, $sCore, 'a core product must outrank an obscure fingerprint');
        self::assertGreaterThan($sMeta, $sObscure, 'a grab-bag META_PID is demoted below an obscure product');
        // The +800 core vs -200 META identity gap is 1000 points.
        self::assertSame(1000, $sCore - $sMeta);
    }

    public function test_known_cve_product_outranks_bare_tail(): void
    {
        $meta = $this->meta(['cveid' => ['cve', 'cve2021'], 'plain' => ['tech']]);
        $known = $this->bundle('someapp', 200, 'high', ['cveid']);      // product + cve tag => +80
        $tail = $this->bundle('anotherapp', 200, 'high', ['plain']);    // product, no cve   => +10

        self::assertGreaterThan(
            $this->cap->keepScore($tail, $meta),
            $this->cap->keepScore($known, $meta)
        );
    }

    public function test_200_realism_beats_status_outlier(): void
    {
        $meta = $this->meta(['x' => ['tech'], 'y' => ['tech']]);
        $ok = $this->bundle('obscure', 200, 'info', ['x']);
        $outlier = $this->bundle('obscure', 404, 'critical', ['y']); // higher sev, but 404 root

        self::assertGreaterThan(
            $this->cap->keepScore($outlier, $meta),
            $this->cap->keepScore($ok, $meta),
            'a 200 identity must beat a critical 404 root outlier'
        );
    }

    public function test_cap_keeps_top_n_and_drops_the_rest(): void
    {
        $meta = [];
        $bundles = [];
        // 41 plausible 200 bundles => one must be cut to reach N=40.
        for ($i = 0; $i < 41; $i++) {
            $id = "t{$i}";
            $meta[$id] = ['sev' => 'info', 'tags' => ['tech'], 'name' => $id];
            $bundles[] = $this->bundle("prod{$i}", 200, 'info', [$id]);
        }

        $result = $this->cap->cap($bundles, $meta);

        self::assertLessThanOrEqual(PersonaCap::N, count($result['kept']));
        self::assertCount(40, $result['kept']);
        self::assertCount(1, $result['dropped']);
        self::assertCount(0, $result['implausible']);
    }

    public function test_cap_drops_implausible_root_status_outliers(): void
    {
        $meta = ['out' => ['sev' => 'critical', 'tags' => ['tech'], 'name' => 'out']];
        // A single 404 outlier plus 40 plausible 200s: the 404 is dropped as implausible
        // even though its severity would otherwise rank it high.
        $bundles = [$this->bundle('bigvendor', 404, 'critical', ['out'])];
        for ($i = 0; $i < 40; $i++) {
            $id = "ok{$i}";
            $meta[$id] = ['sev' => 'info', 'tags' => ['tech'], 'name' => $id];
            $bundles[] = $this->bundle("p{$i}", 200, 'info', [$id]);
        }

        $result = $this->cap->cap($bundles, $meta);

        self::assertCount(1, $result['implausible']);
        self::assertSame('bigvendor', $result['implausible'][0]->product);
        foreach ($result['kept'] as $b) {
            self::assertSame(200, $b->status, 'no status-outlier survives into the served set');
        }
    }

    public function test_error_status_with_vuln_signature_is_kept(): void
    {
        // A 500 that carries a real vuln signature is a legitimate identity, not dropped.
        $meta = ['cveid' => ['sev' => 'critical', 'tags' => ['cve', 'rce'], 'name' => 'cveid']];
        $bundles = [$this->bundle('thinkphp', 500, 'critical', ['cveid'])];

        $result = $this->cap->cap($bundles, $meta);

        self::assertCount(0, $result['implausible'], '500 with a cve signature is a served identity');
        self::assertCount(1, $result['kept']);
    }

    public function test_weight_tiers(): void
    {
        $meta = $this->meta([
            'cveid' => ['cve'],
            'plain' => ['tech'],
        ]);

        self::assertSame(100, $this->cap->weight($this->bundle('nginx', 200, 'info', ['plain']), $meta));
        self::assertSame(30, $this->cap->weight($this->bundle('django', 200, 'info', ['plain']), $meta));
        self::assertSame(8, $this->cap->weight($this->bundle('someapp', 200, 'info', ['cveid']), $meta));
        self::assertSame(2, $this->cap->weight($this->bundle('someapp', 200, 'info', ['plain']), $meta));
        // META_PID never earns a popularity weight above tail.
        self::assertSame(2, $this->cap->weight($this->bundle('discovery', 200, 'info', ['cveid']), $meta));
    }
}
