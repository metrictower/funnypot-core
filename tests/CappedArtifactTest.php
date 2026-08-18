<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * Asserts the persona cap against the shipped full artifact: capped keys serve ≤N
 * bundles yet keep FULL detect coverage on 'd', and every uncapped key keeps the old
 * shape byte-for-byte (no 'd', no per-bundle 'w').
 */
final class CappedArtifactTest extends TestCase
{
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';

    protected function setUp(): void
    {
        if (!is_file(self::INDEX)) {
            self::markTestSkipped('nuclei-index.full.php not built — run bin/funnypot compile');
        }
        ini_set('memory_limit', '512M');
    }

    private function store(): PhpArrayStore
    {
        return PhpArrayStore::fromFile(self::INDEX);
    }

    public function test_root_key_is_capped_but_detect_is_full(): void
    {
        $store = $this->store();
        $entry = $store->lookup('GET /');
        self::assertNotNull($entry);
        self::assertArrayHasKey('d', $entry, 'a capped key carries the full detect id-list');

        // Served set is capped at N=40.
        self::assertLessThanOrEqual(40, count($entry['b']));

        // Detect covers strictly more templates than the served set.
        $served = [];
        foreach ($entry['b'] as $b) {
            foreach ($b['t'] as $id) {
                $served[$id] = true;
            }
        }
        self::assertGreaterThan(count($served), count($entry['d']), 'detect must be a superset of served');
        self::assertGreaterThan(1000, count($entry['d']), 'GET / detect coverage is the full corpus slice');

        // detect() returns the full 'd' set, unaffected by the served cap.
        $d = (new Honeypot($store))->detect(new RequestContext('GET', '/'));
        self::assertTrue($d->matched);
        self::assertSame(count($entry['d']), count($d->templateIds()));
    }

    public function test_every_served_root_bundle_carries_a_weight_and_is_200(): void
    {
        $entry = $this->store()->lookup('GET /');
        foreach ($entry['b'] as $b) {
            self::assertArrayHasKey('w', $b, 'each kept bundle carries an integer selection weight');
            self::assertIsInt($b['w']);
            self::assertSame(200, $b['s'], 'the root host plausibly answers 200, not a status outlier');
        }
    }

    public function test_uncapped_multi_bundle_key_keeps_the_old_shape(): void
    {
        // 27 bundles (< N) — must be untouched: no detect side-list, no weights.
        $entry = $this->store()->lookup('GET /wp-admin/admin-ajax.php');
        self::assertNotNull($entry);
        self::assertArrayNotHasKey('d', $entry, 'an uncapped key must not gain a detect side-list');
        self::assertGreaterThan(1, count($entry['b']));
        foreach ($entry['b'] as $b) {
            self::assertArrayNotHasKey('w', $b, 'an uncapped bundle must not gain a weight');
        }
    }

    public function test_a_dropped_outlier_is_still_detectable(): void
    {
        // The cap removes status-outliers from the SERVED set but never from detect.
        $entry = $this->store()->lookup('GET /');
        $detectIds = array_flip($entry['d']);
        $served = [];
        foreach ($entry['b'] as $b) {
            foreach ($b['t'] as $id) {
                $served[$id] = true;
            }
        }
        // At least one detect id is not served (proves the served set is genuinely capped).
        $unservedButDetected = array_diff_key($detectIds, $served);
        self::assertNotEmpty($unservedButDetected);
    }
}
