<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Behavior;

use Funnypot\Core\Behavior\DecoySessionPayloads;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use PHPUnit\Framework\TestCase;

/**
 * FP-0296 — the closed per-deploy vocabulary for the decoy-session value token. Pins the exact pool
 * and order, that one seed selects exactly one reviewed pair (never two independent draws), that every
 * pair is reachable and fingerprint-clean, and that the derivation is a pure function of the seed alone
 * (no entropy primitive) so a render is byte-stable per deploy.
 */
final class DecoySessionPayloadsTest extends TestCase
{
    public function test_pool_shape_order_and_structural_inequality(): void
    {
        self::assertCount(16, DecoySessionPayloads::PAIRS, 'the reviewed pool is exactly 16 pairs');
        foreach (DecoySessionPayloads::PAIRS as $i => $pair) {
            self::assertArrayHasKey('pre', $pair, "pair {$i} has a pre side");
            self::assertArrayHasKey('authenticated', $pair, "pair {$i} has an authenticated side");
            self::assertNotSame($pair['pre'], $pair['authenticated'], "pair {$i}: the two classes must differ structurally");
        }

        // The first two rows pin the reviewed order (the whole list is order-sensitive because one
        // index selects a row); a reorder would silently change which token every deploy mints.
        self::assertSame(['pre' => 'state=guest', 'authenticated' => 'state=user'], DecoySessionPayloads::PAIRS[0]);
        self::assertSame(['pre' => 'logged_in=0', 'authenticated' => 'logged_in=1'], DecoySessionPayloads::PAIRS[10]);
    }

    public function test_one_index_selects_the_whole_pair(): void
    {
        // pair() must be exactly PAIRS[SubSeed::index(...)] — never two independent picks, or a
        // vocabulary edit could make preAuth() and authenticated() collide.
        foreach ([0, 1, 7, 0x5f0005, 484348449122915112] as $seed) {
            $i = SubSeed::index($seed, SubSeed::NS_DECOY, 'session|payload-pair', 16);
            self::assertSame(DecoySessionPayloads::PAIRS[$i], DecoySessionPayloads::pair($seed), "seed {$seed}");
            self::assertSame(DecoySessionPayloads::PAIRS[$i]['pre'], DecoySessionPayloads::preAuth($seed));
            self::assertSame(DecoySessionPayloads::PAIRS[$i]['authenticated'], DecoySessionPayloads::authenticated($seed));
        }
    }

    public function test_null_maps_to_seed_zero(): void
    {
        self::assertSame(DecoySessionPayloads::pair(0), DecoySessionPayloads::pair(null));
        self::assertSame(DecoySessionPayloads::authenticated(0), DecoySessionPayloads::authenticated(null));
        self::assertSame(DecoySessionPayloads::preAuth(0), DecoySessionPayloads::preAuth(null));
    }

    public function test_derivation_is_deterministic_per_seed(): void
    {
        foreach ([0, 42, 0x5f0005] as $seed) {
            self::assertSame(DecoySessionPayloads::authenticated($seed), DecoySessionPayloads::authenticated($seed));
        }
    }

    public function test_all_pairs_are_reachable_across_a_material_sweep(): void
    {
        $seen = [];
        for ($i = 0; $i < 64; $i++) {
            $seed = PersonaIdentity::seedFromMaterial('fp-0296-' . $i);
            $seen[DecoySessionPayloads::authenticated($seed)] = true;
        }
        self::assertCount(16, $seen, 'all 16 authenticated payloads are reachable across the fp-0296-0..63 sweep');
    }

    public function test_pinned_sample_materials_diverge(): void
    {
        // The two fixed gate materials must select DIFFERENT pairs, so the seeded-render gate's G4 is
        // non-colliding on the session: surface.
        $a = PersonaIdentity::seedFromMaterial('fp-0276-sample-a');
        $b = PersonaIdentity::seedFromMaterial('fp-0276-sample-b');
        self::assertNotSame(
            DecoySessionPayloads::authenticated($a),
            DecoySessionPayloads::authenticated($b),
            'the two pinned sample deploys must mint different value tokens'
        );
    }

    public function test_every_payload_is_fingerprint_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach (DecoySessionPayloads::PAIRS as $i => $pair) {
            self::assertSame([], $guard->scan($pair['pre']), "pair {$i} pre must be denylist-clean");
            self::assertSame([], $guard->scan($pair['authenticated']), "pair {$i} authenticated must be denylist-clean");
        }
    }

    public function test_source_uses_no_entropy_primitive(): void
    {
        // A per-deploy value must derive from the seed alone: no clock, CSPRNG, request byte, or the
        // 64-bit-only SubSeed::int — only SubSeed::index (the 32-bit-safe served-offset reduction).
        $src = file_get_contents(__DIR__ . '/../../src/Behavior/DecoySessionPayloads.php');
        self::assertNotFalse($src);
        foreach (['SubSeed::int(', 'rand', 'mt_rand', 'random_', 'time(', 'microtime', 'uniqid', 'hrtime'] as $needle) {
            self::assertStringNotContainsString($needle, $src, "DecoySessionPayloads must not use {$needle}");
        }
        self::assertStringContainsString('SubSeed::index(', $src, 'the selection must use the 32-bit-safe index reduction');
    }
}
