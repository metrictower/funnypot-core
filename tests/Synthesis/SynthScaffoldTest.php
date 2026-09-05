<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Synthesis;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use Funnypot\Core\Synthesis\SynthScaffold;
use PHPUnit\Framework\TestCase;

/**
 * Contract for the FP-0281 minimal-synth scaffold helper: the body word order and the witness-header
 * names are a pure, deterministic function of the deploy identity seed; they vary across deploys; and
 * every pool name is marker-safe against the shipped nuclei index (the proof that a renamed witness
 * header can neither break nor spuriously over-satisfy a matcher — M2). Sweeps many seeds, not seed 0
 * alone.
 */
final class SynthScaffoldTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index = null;

    /** @return array<string,mixed> */
    private static function index(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }

    /** Go textproto.CanonicalMIMEHeaderKey — the 10-line canonicaliser ResponseSynthesizer applies. */
    private static function canonicalKey(string $name): string
    {
        $out = '';
        $upperNext = true;
        $len = strlen($name);
        for ($i = 0; $i < $len; $i++) {
            $ch = $name[$i];
            if ($ch === '-') {
                $out .= $ch;
                $upperNext = true;
                continue;
            }
            $out .= $upperNext ? strtoupper($ch) : strtolower($ch);
            $upperNext = false;
        }

        return $out;
    }

    // --- determinism ------------------------------------------------------------------------------

    public function test_body_order_and_names_are_deterministic_per_seed(): void
    {
        foreach ([0, 1, 4242, 813047441495709120] as $seed) {
            $words = ['alpha', 'bravo', 'charlie', 'delta'];
            self::assertSame(
                SynthScaffold::bodyOrder($words, $seed),
                SynthScaffold::bodyOrder($words, $seed),
                "bodyOrder deterministic at seed {$seed}"
            );
            self::assertSame(
                SynthScaffold::witnessHeaderNames($seed),
                SynthScaffold::witnessHeaderNames($seed),
                "witnessHeaderNames deterministic at seed {$seed}"
            );
        }
    }

    public function test_body_order_is_a_permutation_preserving_the_multiset(): void
    {
        $words = ['Index of /config', 'Parent Directory', 'zzz', 'aaa', 'mmm'];
        foreach ([1, 2, 7, 4242, 99] as $seed) {
            $ordered = SynthScaffold::bodyOrder($words, $seed);
            self::assertCount(count($words), $ordered, "count preserved at seed {$seed}");
            $a = $words;
            $b = $ordered;
            sort($a);
            sort($b);
            self::assertSame($a, $b, "no word lost or duplicated at seed {$seed}");
        }
        self::assertSame([], SynthScaffold::bodyOrder([], 5), 'empty list unchanged');
        self::assertSame(['one'], SynthScaffold::bodyOrder(['one'], 5), 'single-word body stays fleet-constant');
    }

    public function test_witness_header_names_are_14_canonical_pool_names(): void
    {
        $pool = array_flip(SynthScaffold::allNames());
        foreach ([0, 1, 4242, 99, 813047441495709120] as $seed) {
            $names = SynthScaffold::witnessHeaderNames($seed);
            self::assertCount(count(SynthScaffold::NAME_FIRST), $names, "one name per first-part at seed {$seed}");
            self::assertSame(count($names), count(array_unique($names)), "names distinct at seed {$seed}");
            foreach ($names as $n) {
                self::assertArrayHasKey($n, $pool, "{$n} is a pool name at seed {$seed}");
                self::assertSame(self::canonicalKey($n), $n, "{$n} is Go-canonical");
            }
            // one coherent suffix per deploy (the point of per-deploy naming)
            $suffixes = [];
            foreach ($names as $n) {
                $suffixes[substr($n, strrpos($n, '-') + 1)] = true;
            }
            self::assertCount(1, $suffixes, "one coherent suffix per deploy at seed {$seed}");
        }
    }

    // --- independence + cross-deploy variance -----------------------------------------------------

    public function test_body_order_draws_independently_per_bundle(): void
    {
        // The field keys on the word list itself, so two different 4-word bundles do NOT share one
        // permutation shape at every seed (a fixed field would force all 4-word bundles into one order).
        $listA = ['a', 'b', 'c', 'd'];
        $listB = ['w', 'x', 'y', 'z'];
        $differ = false;
        foreach (range(1, 8) as $seed) {
            $pa = SynthScaffold::bodyOrder($listA, $seed);
            $pb = SynthScaffold::bodyOrder($listB, $seed);
            // Compare the permutation SHAPE (index order), not the letters.
            $shapeA = array_map(static function ($v) use ($listA) { return array_search($v, $listA, true); }, $pa);
            $shapeB = array_map(static function ($v) use ($listB) { return array_search($v, $listB, true); }, $pb);
            if ($shapeA !== $shapeB) {
                $differ = true;
                break;
            }
        }
        self::assertTrue($differ, 'two bundles must draw different permutation shapes for at least one seed');
    }

    public function test_names_vary_across_deploys(): void
    {
        $firsts = [];
        $lists = [];
        for ($i = 0; $i < 64; $i++) {
            $seed = PersonaIdentity::seedFromMaterial("m-{$i}");
            $names = SynthScaffold::witnessHeaderNames($seed);
            $firsts[$names[0]] = true;
            $lists[implode(',', $names)] = true;
        }
        self::assertGreaterThanOrEqual(40, count($firsts), 'many distinct first names across 64 deploys');
        self::assertCount(64, $lists, 'all 64 deploys yield distinct full name lists');
    }

    public function test_body_order_varies_across_deploys(): void
    {
        $words = ['alpha', 'bravo', 'charlie', 'delta'];
        $orders = [];
        for ($i = 0; $i < 16; $i++) {
            $seed = PersonaIdentity::seedFromMaterial("m-{$i}");
            $orders[implode('|', SynthScaffold::bodyOrder($words, $seed))] = true;
        }
        self::assertGreaterThanOrEqual(10, count($orders), 'a 4-word body reaches many distinct orders across deploys');
    }

    public function test_the_two_gate_sample_materials_pin_distinct_first_names(): void
    {
        // The exact pair the seeded-render gate's G4 compares — pins the SubSeed derivation so a drift
        // in the pick/permute math is caught here as well as in the gate.
        $a = SynthScaffold::witnessHeaderNames(PersonaIdentity::seedFromMaterial('fp-0276-sample-a'));
        $b = SynthScaffold::witnessHeaderNames(PersonaIdentity::seedFromMaterial('fp-0276-sample-b'));
        self::assertSame('X-Upstream-Ctx', $a[0]);
        self::assertSame('X-Trace-Scope', $b[0]);
        self::assertNotSame($a[0], $b[0], 'G4 needs the two sample materials to differ on day one');
    }

    // --- pool hygiene: the marker-safety proof for the names --------------------------------------

    public function test_every_pool_name_is_denylist_and_shape_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $reserved = array_flip(SynthScaffold::RESERVED);
        foreach (SynthScaffold::allNames() as $name) {
            self::assertSame(self::canonicalKey($name), $name, "{$name} is Go-canonical");
            self::assertSame(0, preg_match('/[\r\n\x00]/', $name), "{$name} is CR/LF/NUL-free");
            self::assertSame([], $guard->scan($name), "{$name} carries no fingerprint-denylist token");
            self::assertFalse(SubSeed::hitsDeniedDigits($name), "{$name} carries no bare CRS digit");
            self::assertArrayNotHasKey($name, $reserved, "{$name} is not a reserved/chrome name");
            foreach (['goog', 'xss', 'cloudflare', 'cache', 'cookie', 'content', 'request'] as $bad) {
                self::assertFalse(stripos($name, $bad) !== false, "{$name} avoids the real header family '{$bad}'");
            }
        }
    }

    public function test_no_pool_name_collides_with_index_hf_or_th(): void
    {
        $names = SynthScaffold::allNames();
        [$hw, $hf, $th] = $this->indexWitnessSets();

        foreach ($names as $name) {
            foreach (array_keys($hf) as $bad) {
                self::assertFalse(stripos($name, (string) $bad) !== false, "pool name {$name} must not contain hf substring '{$bad}'");
            }
            self::assertArrayNotHasKey($name, $th, "pool name {$name} must not equal a typed-header name");
        }
    }

    public function test_no_index_hw_word_is_a_substring_of_any_pool_name(): void
    {
        // M2 (regression lock): a pool name that CONTAINED an hw word would silently over-satisfy that
        // header matcher on every witness-bearing response of a deploy — a fleet-wide "this host is every
        // product" tell. True today (0 collisions); this pins it so a future pool/corpus edit can't
        // reintroduce one.
        $names = SynthScaffold::allNames();
        [$hw] = $this->indexWitnessSets();
        foreach (array_keys($hw) as $word) {
            $word = (string) $word;
            if ($word === '') {
                continue;
            }
            foreach ($names as $name) {
                self::assertFalse(stripos($name, $word) !== false, "hw word '{$word}' must not be a substring of pool name {$name}");
                self::assertFalse(stripos($name . ': ', $word) !== false, "hw word '{$word}' must not be a substring of the header line for {$name}");
            }
        }
    }

    public function test_the_pool_covers_the_index_maximum_witness_count(): void
    {
        $max = 0;
        foreach (self::index()['routes'] ?? [] as $entry) {
            foreach ((array) ($entry['b'] ?? []) as $bundle) {
                if (is_array($bundle)) {
                    $max = max($max, count((array) ($bundle['hw'] ?? [])));
                }
            }
        }
        self::assertLessThanOrEqual(count(SynthScaffold::NAME_FIRST), $max, 'the name pool must cover the corpus max hw count without hitting the overflow path');
    }

    // --- 32-bit safety ----------------------------------------------------------------------------

    public function test_the_helper_never_calls_the_64bit_only_subseed_int(): void
    {
        $src = (string) file_get_contents(__DIR__ . '/../../src/Synthesis/SynthScaffold.php');
        self::assertStringNotContainsString('SubSeed::int(', $src, 'only pick/permute (32-bit-safe) may be used on the served path');
    }

    /**
     * @return array{0:array<string,bool>,1:array<string,bool>,2:array<string,bool>}
     */
    private function indexWitnessSets(): array
    {
        $hw = [];
        $hf = [];
        $th = [];
        foreach (self::index()['routes'] ?? [] as $entry) {
            foreach ((array) ($entry['b'] ?? []) as $bundle) {
                if (!is_array($bundle)) {
                    continue;
                }
                foreach ((array) ($bundle['hw'] ?? []) as $w) {
                    $hw[(string) $w] = true;
                }
                foreach ((array) ($bundle['hf'] ?? []) as $w) {
                    $hf[(string) $w] = true;
                }
                foreach ((array) ($bundle['th'] ?? []) as $name => $_subs) {
                    $th[(string) $name] = true;
                }
            }
        }

        return [$hw, $hf, $th];
    }
}
