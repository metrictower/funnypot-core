<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Behavior;

use Funnypot\Core\Behavior\DecoyTables;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use PHPUnit\Framework\TestCase;

/**
 * DecoyTables (FP-0282) is the ONE source of the authed phpMyAdmin decoy's table story. These tests pin
 * the load-bearing invariants:
 *  - the `?table=` whitelist is a genuine PROJECTION of the seeded forDeploy() array (it can never
 *    advertise a name it rejects, or accept a name it does not show) — the #1 correlation-drift risk;
 *  - the story is a pure function of the deploy seed (deterministic within a deploy, varying across);
 *  - the row-shape law: column COUNT and ORDER per kind are FakeRecords' positional shapes and never
 *    change; only the {ts:*} label slots vary, all through ONE per-deploy convention;
 *  - pool hygiene: names/labels are letters/underscore, fingerprint-clean, disjoint across kinds (which
 *    is what makes the alphabetical usort tie-free, hence order-deterministic on PHP 7.3).
 *
 * Every assertion fails at baseline `1ac81d3` (the class did not exist).
 */
final class DecoyTablesTest extends TestCase
{
    private const GATE_A = 'fp-0276-sample-a';
    private const GATE_B = 'fp-0276-sample-b';

    /** @return list<int> a spread of deploy seeds: the two gate materials + '' + 'funnypot' + 60 more. */
    private function seeds(): array
    {
        $seeds = [
            PersonaIdentity::seedFromMaterial(''),
            PersonaIdentity::seedFromMaterial('funnypot'),
            PersonaIdentity::seedFromMaterial(self::GATE_A),
            PersonaIdentity::seedFromMaterial(self::GATE_B),
        ];
        for ($i = 0; $i < 60; $i++) {
            $seeds[] = PersonaIdentity::seedFromMaterial('m-' . $i);
        }

        return $seeds;
    }

    // --- determinism + shape ----------------------------------------------------------------

    public function test_for_deploy_is_deterministic_and_well_shaped(): void
    {
        foreach ($this->seeds() as $seed) {
            $story = DecoyTables::forDeploy($seed);
            self::assertSame($story, DecoyTables::forDeploy($seed), 'forDeploy must be a pure function of the seed');

            $names = [];
            $sorted = $story;
            usort($sorted, static function (array $a, array $b): int {
                return strcmp($a['name'], $b['name']);
            });
            self::assertSame($sorted, $story, 'the story must be sorted alphabetically by name');

            foreach ($story as $t) {
                self::assertContains($t['kind'], DecoyTables::KINDS, 'kind must be canonical');
                self::assertContains($t['name'], DecoyTables::NAMES[$t['kind']], 'name must come from the kind pool');
                // Row-shape law: the deploy's columns for a kind have the SAME count as the canonical shape.
                self::assertCount(
                    count(DecoyTables::COLUMNS[$t['kind']]),
                    $t['columns'],
                    'column count is FakeRecords\' positional row shape and must never change (kind ' . $t['kind'] . ')'
                );
                $names[] = $t['name'];
            }
            self::assertSame(array_values(array_unique($names)), $names, 'served names must be unique within a deploy');
        }
    }

    // --- the #1 risk: whitelist ≡ tree, mechanically ----------------------------------------

    public function test_whitelist_is_exactly_the_tree_and_resolves_default_to_users(): void
    {
        foreach ($this->seeds() as $seed) {
            $whitelist = DecoyTables::whitelist($seed);
            $names = DecoyTables::names($seed);

            // The accept-set keys ARE the tree, in the same order.
            self::assertSame(array_keys($whitelist), $names, 'whitelist keys must equal the tree, in order');

            // For every pool name: accepted iff shown. No name can be accepted-but-hidden or shown-but-rejected.
            foreach (DecoyTables::allNames() as $n) {
                self::assertSame(
                    in_array($n, $names, true),
                    isset($whitelist[$n]),
                    'accepted iff shown must hold for ' . $n
                );
            }

            // The default view is the users kind; users and secrets are never dropped.
            self::assertSame('users', $whitelist[DecoyTables::defaultName($seed)], 'default resolves to the users kind');
            self::assertNotNull(DecoyTables::nameOf($seed, 'users'), 'users is never dropped');
            self::assertNotNull(DecoyTables::nameOf($seed, 'secrets'), 'secrets (the FLAG lure) is never dropped');

            // columns() agrees with the forDeploy entry for every served kind.
            foreach (DecoyTables::forDeploy($seed) as $t) {
                self::assertSame($t['columns'], DecoyTables::columns($seed, $t['kind']), 'columns() must match forDeploy for ' . $t['kind']);
            }
        }
    }

    public function test_one_timestamp_convention_per_deploy(): void
    {
        foreach ($this->seeds() as $seed) {
            // Which TS_STYLES row is this deploy using? Determine it from the users table's created slot,
            // then assert every kind's {ts:*} columns come from that SAME row (a real schema is consistent).
            $styleIdx = null;
            foreach (DecoyTables::TS_STYLES as $idx => $row) {
                if (DecoyTables::columns($seed, 'users')[3] === $row['created']) {
                    $styleIdx = $idx;
                    break;
                }
            }
            self::assertNotNull($styleIdx, 'the users created-column must match exactly one TS_STYLES row');

            foreach (DecoyTables::forDeploy($seed) as $t) {
                $raw = DecoyTables::COLUMNS[$t['kind']];
                foreach ($raw as $pos => $rawCol) {
                    if (preg_match('/^\{ts:([a-z_]+)\}$/', $rawCol, $m) === 1) {
                        self::assertSame(
                            DecoyTables::TS_STYLES[$styleIdx][$m[1]],
                            $t['columns'][$pos],
                            'every {ts:*} slot must follow the deploy\'s one convention (kind ' . $t['kind'] . ')'
                        );
                    } else {
                        self::assertSame($rawCol, $t['columns'][$pos], 'a non-timestamp label must pass through verbatim');
                    }
                }
            }
        }
    }

    public function test_columns_throws_on_an_unknown_kind(): void
    {
        $this->expectException(\RuntimeException::class);
        DecoyTables::columns(0, 'not_a_kind');
    }

    // --- cross-deploy variance --------------------------------------------------------------

    public function test_the_table_set_varies_across_deploys(): void
    {
        $distinct = [];
        $sizes = [];
        $reproduceToday = 0;
        // Sorted copy of today's former fleet constant (the six literals, any order).
        $today = ['api_keys', 'orders', 'password_resets', 'secrets', 'sessions', 'users'];

        foreach ($this->seeds() as $seed) {
            $names = DecoyTables::names($seed);
            sort($names);
            $distinct[implode(',', $names)] = true;
            $sizes[count($names)] = ($sizes[count($names)] ?? 0) + 1;
            if ($names === $today) {
                $reproduceToday++;
            }
        }

        self::assertGreaterThanOrEqual(60, count($distinct), 'the seeded table set must vary widely across deploys');
        self::assertArrayHasKey(6, $sizes, 'some deploys keep all six tables');
        self::assertArrayHasKey(5, $sizes, 'some deploys drop one optional table');
        // The former fleet constant is essentially unreachable (measured 0/64); a loose bound stays
        // robust to pool tuning while still proving the six-name correlation is gone.
        self::assertLessThan(4, $reproduceToday, 'the old six-name fleet constant must not be a common draw');
    }

    public function test_the_two_gate_materials_draw_different_stories(): void
    {
        // The seeded-render gate compares these exact two materials for the phpMyAdmin authed surface;
        // pin that they differ so that G4 pin is non-vacuous.
        $a = DecoyTables::names(PersonaIdentity::seedFromMaterial(self::GATE_A));
        $b = DecoyTables::names(PersonaIdentity::seedFromMaterial(self::GATE_B));
        self::assertNotSame($a, $b, 'the gate pair must draw different table stories');
    }

    // --- pool hygiene (load-bearing for determinism AND fingerprint safety) -----------------

    public function test_pools_are_disjoint_across_kinds(): void
    {
        $seen = [];
        foreach (DecoyTables::NAMES as $kind => $pool) {
            foreach ($pool as $name) {
                self::assertArrayNotHasKey(
                    $name,
                    $seen,
                    'pools must be pairwise disjoint (load-bearing: it keeps the alphabetical usort tie-free, hence order-deterministic on PHP 7.3\'s unstable sort) — "' . $name . '" collides'
                );
                $seen[$name] = $kind;
            }
        }
        self::assertCount(count(DecoyTables::allNames()), $seen);
    }

    public function test_every_served_name_and_label_is_hygienic(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach ($this->seeds() as $seed) {
            foreach (DecoyTables::forDeploy($seed) as $t) {
                $tokens = array_merge([$t['name']], $t['columns']);
                foreach ($tokens as $tok) {
                    self::assertMatchesRegularExpression('/^[a-z][a-z0-9_]*$/', $tok, 'names/labels are lowercase letters/underscore only: ' . $tok);
                    self::assertSame([], $guard->scan($tok), 'no name/label may carry an upstream-detector signature: ' . $tok);
                    self::assertFalse(SubSeed::hitsDeniedDigits($tok), 'no name/label may hit the denied-digit pattern: ' . $tok);
                    // The reflection-negative pin in PhpMyAdminAuthedDashboardTest stays meaningful only
                    // if no pool name contains these substrings.
                    self::assertStringNotContainsString('etc', $tok);
                    self::assertStringNotContainsString('passwd', $tok);
                }
            }
        }
    }

    // --- determinism-primitive discipline ---------------------------------------------------

    public function test_source_uses_only_32bit_safe_seeded_index_under_ns_decoy(): void
    {
        $src = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Behavior/DecoyTables.php');
        // Never SubSeed::int() (64-bit-only) on this served path.
        self::assertStringNotContainsString('SubSeed::int(', $src, 'the served table story must never use the 64-bit-only int()');
        // Never a hand-rolled decoy namespace tag — every derivation must go through the SubSeed NS.
        self::assertStringNotContainsString("'|decoy|'", $src, 'derivations must use SubSeed::NS_DECOY, not a hand-rolled tag');
    }
}
