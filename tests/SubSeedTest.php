<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;

/**
 * SubSeed is the FP-0276 deploy-seed sub-derivation primitive. Its LOAD-BEARING contract is
 * byte-identity: digest()/index()/chars()/reroll() reproduce the three inline derivations that ship
 * today, so migrating those call sites to it re-rolls NO deployed persona/fake/visual. This test pins
 * that at three levels — the raw digest formula, the index/reduction, AND the RENDERED output through
 * the real render paths (the N1 nit: goldens for fake AND visual, not just the digest) — plus the
 * general API contract and the NS-registry lint that stops a sibling inventing an unregistered tag.
 *
 * The rendered goldens are the bytes produced at a469c71 (the migration baseline); a single-byte
 * change to any derivation fails them loudly.
 */
final class SubSeedTest extends TestCase
{
    // --- byte-identity: the raw digest formula for the three existing namespaces ------------------

    public function test_digest_reproduces_the_persona_fake_visual_formulas(): void
    {
        foreach ([0, 1, 7, 4242, 67142204528030646] as $seed) {
            foreach (['company', 'db_pw', 'jwt_secret', 'x', ''] as $field) {
                self::assertSame(
                    hash('sha256', $seed . '|persona|' . $field),
                    SubSeed::digest($seed, SubSeed::NS_PERSONA, $field),
                    "persona seed={$seed} field={$field}"
                );
                self::assertSame(
                    hash('sha256', $seed . '|fake|' . $field),
                    SubSeed::digest($seed, SubSeed::NS_FAKE, $field),
                    "fake seed={$seed} field={$field}"
                );
                self::assertSame(
                    hash('sha256', $seed . '|visual|' . $field),
                    SubSeed::digest($seed, SubSeed::NS_VISUAL, $field),
                    "visual seed={$seed} field={$field}"
                );
            }
        }
    }

    /** index() must equal `hexdec(substr(digest,0,8)) % n` on 64-bit — the PersonaIdentity/VisualPersona pick formula. */
    public function test_index_matches_the_legacy_hexdec_modulo_on_64bit(): void
    {
        if (PHP_INT_SIZE < 8) {
            self::markTestSkipped('64-bit equivalence pin is meaningful only on a 64-bit runner.');
        }
        foreach ([0, 1, 7, 4242] as $seed) {
            foreach (['company', 'tld', 'salt', 'x'] as $field) {
                foreach ([1, 2, 3, 5, 7, 9, 13, 40, 64, 1000] as $n) {
                    $digest = hash('sha256', $seed . '|persona|' . $field);
                    $expected = (int) (hexdec(substr($digest, 0, 8)) % $n);
                    self::assertSame($expected, SubSeed::index($seed, SubSeed::NS_PERSONA, $field, $n), "seed={$seed} field={$field} n={$n}");
                }
            }
        }
    }

    // --- byte-identity: RENDERED-level goldens (N1) -----------------------------------------------

    /** {{fake.x:hex:16}} / :b64:44 / :dec:8 through DirectiveRenderer at 3 render seeds — captured at a469c71. */
    public function test_rendered_fake_goldens_are_unchanged(): void
    {
        $golden = [
            1 => 'd8296e32df6166c6|2CluMt9hZsarPwwdki4ZFJOC0lRxd51J2dBXrN+gsJ8=|61003728',
            7 => '0a3aae82bd730c81|Cjqugr1zDIFzwVEmimyRdcqcHTPAYIgpo1WvS4+TA00=|84095295',
            4242 => '5effe1b36f5275ac|Xv/hs29Sdawdmwy5eSJUrMow7y2Q3VoX+pWPrj2pA0g=|45912729',
        ];
        $r = new DirectiveRenderer();
        foreach ($golden as $seed => $expected) {
            self::assertSame($expected, $r->render('{{fake.x:hex:16}}|{{fake.x:b64:44}}|{{fake.x:dec:8}}', [], $seed), "fake render seed={$seed}");
        }
    }

    /** VisualPersona palette() + pick() at 3 seeds — captured at a469c71 (the {{visual|*}} surface). */
    public function test_rendered_visual_goldens_are_unchanged(): void
    {
        $palettes = [
            1 => ['bg' => '#e0c8d7', 'fg' => '#1b1e21', 'accent' => '#231931', 'muted' => '#6b7280', 'border' => '#c6ecf2'],
            7 => ['bg' => '#d6bfe2', 'fg' => '#1b1e21', 'accent' => '#3910f3', 'muted' => '#6b7280', 'border' => '#c6d5e4'],
            4242 => ['bg' => '#f5c8c9', 'fg' => '#1b1e21', 'accent' => '#ac3b8e', 'muted' => '#6b7280', 'border' => '#edf7cf'],
        ];
        $picks = [1 => 'd', 7 => 'e', 4242 => 'c'];
        foreach ($palettes as $seed => $palette) {
            $vp = VisualPersona::fromSeed($seed);
            self::assertSame($palette, $vp->palette(), "palette seed={$seed}");
            self::assertSame($picks[$seed], $vp->pick('salt', ['a', 'b', 'c', 'd', 'e']), "pick seed={$seed}");
        }
    }

    /** A whole PersonaIdentity field set for a fixed material — the persona-level byte pin. */
    public function test_persona_identity_golden_is_unchanged(): void
    {
        $id = PersonaIdentity::fromSeed(PersonaIdentity::seedFromMaterial('acme'));
        self::assertSame('Yandric', $id->field('company.name'));
        self::assertSame('yandric.tech', $id->field('company.domain'));
        self::assertSame('webadmin', $id->field('user.admin.username'));
        self::assertSame('srL.hkn!VjtUnrmE', $id->field('user.admin.password'));
        self::assertSame('AKIANFLMU2RCMJNXVMPL', $id->field('cloud.aws.accessKeyId'));
        self::assertSame('fp-7219', $id->field('classPrefix'));
        self::assertSame('Lh-xUkfXvpZyvPTfK6sf', $id->field('db.password'));
    }

    // --- general API contract ---------------------------------------------------------------------

    public function test_int_is_a_non_negative_60_bit_value(): void
    {
        if (PHP_INT_SIZE < 8) {
            self::markTestSkipped('int() is 64-bit-only by design (15 hex overflows a 32-bit int).');
        }
        for ($seed = 0; $seed < 200; $seed++) {
            $v = SubSeed::int($seed, SubSeed::NS_CANNED, 'passwd');
            self::assertGreaterThanOrEqual(0, $v);
            self::assertLessThan(1 << 60, $v);
            self::assertSame((int) hexdec(substr(SubSeed::digest($seed, SubSeed::NS_CANNED, 'passwd'), 0, 15)), $v);
        }
    }

    public function test_pick_returns_empty_on_empty_list_and_a_member_otherwise(): void
    {
        self::assertSame('', SubSeed::pick([], 5, SubSeed::NS_SURFACE, 'x'));
        $opts = ['a', 'b', 'c'];
        for ($seed = 0; $seed < 50; $seed++) {
            self::assertContains(SubSeed::pick($opts, $seed, SubSeed::NS_SURFACE, 'noun'), $opts);
        }
    }

    public function test_index_is_zero_for_a_non_positive_count(): void
    {
        self::assertSame(0, SubSeed::index(1, SubSeed::NS_SURFACE, 'x', 0));
        self::assertSame(0, SubSeed::index(1, SubSeed::NS_SURFACE, 'x', -3));
    }

    public function test_permute_is_a_stable_permutation_losing_no_item(): void
    {
        foreach ([0, 1, 2, 7, 64] as $n) {
            $items = $n === 0 ? [] : range(1, $n);
            $p = SubSeed::permute($items, 99, SubSeed::NS_SCAFFOLD, 'order');
            self::assertCount($n, $p, "n={$n} length preserved");
            $sorted = $p;
            sort($sorted);
            self::assertSame($items, $sorted, "n={$n} no item lost or duplicated");
            // Stable per (seed, ns, field).
            self::assertSame(
                SubSeed::permute($items, 99, SubSeed::NS_SCAFFOLD, 'order'),
                SubSeed::permute($items, 99, SubSeed::NS_SCAFFOLD, 'order'),
                "n={$n} stable"
            );
        }
        // Different fields decorrelate for a non-trivial list.
        $a = SubSeed::permute(range(1, 20), 99, SubSeed::NS_SCAFFOLD, 'order-a');
        $b = SubSeed::permute(range(1, 20), 99, SubSeed::NS_SCAFFOLD, 'order-b');
        self::assertNotSame($a, $b, 'distinct fields should not permute identically');
    }

    public function test_subset_clamps_and_is_a_permute_prefix(): void
    {
        $items = range(1, 10);
        self::assertSame([], SubSeed::subset($items, 0, 1, SubSeed::NS_SURFACE, 'k'));
        self::assertSame([], SubSeed::subset($items, -4, 1, SubSeed::NS_SURFACE, 'k'));
        self::assertCount(3, SubSeed::subset($items, 3, 1, SubSeed::NS_SURFACE, 'k'));
        self::assertCount(10, SubSeed::subset($items, 99, 1, SubSeed::NS_SURFACE, 'k'), 'k > count clamps to count');
        $full = SubSeed::permute($items, 1, SubSeed::NS_SURFACE, 'k');
        self::assertSame(array_slice($full, 0, 4), SubSeed::subset($items, 4, 1, SubSeed::NS_SURFACE, 'k'));
    }

    /** chars() must equal PersonaIdentity::password()'s inner loop for length <= 32 (one digest). */
    public function test_chars_matches_the_password_inner_loop(): void
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789-_';
        $n = strlen($alphabet);
        foreach ([1, 7, 4242] as $seed) {
            foreach (['db_pw', 'admin_pw', 'x'] as $field) {
                foreach ([1, 8, 16, 20, 32] as $length) {
                    $digest = hash('sha256', $seed . '|persona|' . $field);
                    $oracle = '';
                    for ($i = 0; $i < $length; $i++) {
                        $oracle .= $alphabet[hexdec(substr($digest, $i * 2, 2)) % $n];
                    }
                    self::assertSame($oracle, SubSeed::chars($seed, SubSeed::NS_PERSONA, $field, $alphabet, $length), "seed={$seed} field={$field} len={$length}");
                }
            }
        }
    }

    public function test_chars_chains_past_one_digest(): void
    {
        // 40 chars needs a second block; assert it is deterministic and the right length.
        $v = SubSeed::chars(1, SubSeed::NS_CANNED, 'long', '0123456789abcdef', 40);
        self::assertSame(40, strlen($v));
        self::assertSame($v, SubSeed::chars(1, SubSeed::NS_CANNED, 'long', '0123456789abcdef', 40));
    }

    public function test_chars_is_empty_for_degenerate_input(): void
    {
        self::assertSame('', SubSeed::chars(1, SubSeed::NS_CANNED, 'x', 'abc', 0));
        self::assertSame('', SubSeed::chars(1, SubSeed::NS_CANNED, 'x', '', 10));
    }

    // --- reroll -----------------------------------------------------------------------------------

    public function test_reroll_tags_rounds_and_defaults_to_hits_denied_digits(): void
    {
        $seen = [];
        // Reject the first two candidates, accept the third — proving the round tagging f, f|r1, f|r2.
        $out = SubSeed::reroll('pw', function (string $field) use (&$seen): string {
            $seen[] = $field;

            return count($seen) < 3 ? '900000' : 'clean';
        });
        self::assertSame('clean', $out);
        self::assertSame(['pw', 'pw|r1', 'pw|r2'], $seen);
    }

    public function test_reroll_default_reject_is_the_denied_digit_predicate(): void
    {
        // A generator that always yields a denied bare-6-digit token exhausts and throws.
        $this->expectException(\RuntimeException::class);
        SubSeed::reroll('pw', static function (): string {
            return 'x 900000 y';
        }, null, 4);
    }

    public function test_reroll_throws_when_max_rounds_exhausted(): void
    {
        $this->expectException(\RuntimeException::class);
        SubSeed::reroll('pw', static function (): string {
            return 'nope';
        }, static function (): bool {
            return true; // reject everything
        }, 8);
    }

    // --- hitsDeniedDigits pinned to the denylist --------------------------------------------------

    public function test_hits_denied_digits_pins_the_denylist_entry(): void
    {
        $denylist = require dirname(__DIR__) . '/resources/fingerprint-denylist.php';
        self::assertContains('\b9\d{5}\b', $denylist['patterns'], 'the SubSeed predicate must match the denylist bare-CRS-id pattern');

        self::assertTrue(SubSeed::hitsDeniedDigits('prefix 900123 suffix'));
        self::assertTrue(SubSeed::hitsDeniedDigits('900123'));
        self::assertFalse(SubSeed::hitsDeniedDigits('9001234'), 'a 7-digit run is not the bare 6-digit token');
        self::assertFalse(SubSeed::hitsDeniedDigits('abcdef0123456789abcdef'));
    }

    // --- NS-registry lint (N2) --------------------------------------------------------------------

    /**
     * Every two-pipe sub-seed tag `. '|<ns>|'` in src/ must be a registered SubSeed NS_* value or one
     * of the documented legacy tags. A sibling that hand-rolls an unregistered `'|foo|'` hash tag fails
     * here. (Single-sided tags like `$seed.'|misdirect'` / `$seed.'|fakehex'` are NOT `'|x|'`-shaped
     * and are governed separately — see the class docblocks that own them.)
     */
    public function test_ns_registry_lint_covers_every_two_pipe_hash_tag(): void
    {
        $allowed = [
            // SubSeed NS_* registry
            'persona', 'fake', 'visual', 'canned', 'surface', 'attack', 'witness', 'scaffold', 'honeytoken', 'decoy',
            // documented legacy tags (not de-triplicated by this ticket)
            'pick', 'token', 'awskey', 'product-version', 'secret', 'person', 'record', 'labelorder',
        ];
        $found = [];
        $offenders = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(dirname(__DIR__) . '/src', \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $src = (string) file_get_contents($file->getPathname());
            // A two-pipe tag literal used in a concatenation (either side of a '.').
            if (preg_match_all("/(?:\\.\\s*'\\|([a-z0-9_-]+)\\|')|(?:'\\|([a-z0-9_-]+)\\|'\\s*\\.)/", $src, $m)) {
                foreach (array_merge($m[1], $m[2]) as $tag) {
                    if ($tag === '') {
                        continue;
                    }
                    $found[$tag] = true;
                    if (!in_array($tag, $allowed, true)) {
                        $offenders[$tag] = $file->getPathname();
                    }
                }
            }
        }
        self::assertSame([], $offenders, 'unregistered sub-seed namespace tag(s): ' . implode(', ', array_keys($offenders)));
        // Non-vacuous: the three migrated namespaces must actually be observed.
        foreach (['persona', 'fake', 'visual'] as $core) {
            self::assertArrayHasKey($core, $found, "the lint should observe the '{$core}' namespace in src/");
        }
    }
}
