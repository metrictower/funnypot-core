<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests\Support;

use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class VisualPersonaTest extends TestCase
{
    public function test_deterministic_per_seed(): void
    {
        $a = VisualPersona::fromSeed(123);
        $b = VisualPersona::fromSeed(123);
        self::assertSame($a->classPrefix(), $b->classPrefix());
        self::assertSame($a->palette(), $b->palette());
        self::assertSame($a->fakeToken('cell00'), $b->fakeToken('cell00'));
    }

    public function test_different_seeds_diverge(): void
    {
        self::assertNotSame(VisualPersona::fromSeed(1)->classPrefix(), VisualPersona::fromSeed(2)->classPrefix());
        self::assertNotSame(VisualPersona::fromSeed(1)->palette()['accent'], VisualPersona::fromSeed(2)->palette()['accent']);
    }

    public function test_palette_is_hex_and_token_shape(): void
    {
        $p = VisualPersona::fromSeed(7);
        foreach ($p->palette() as $c) {
            self::assertMatchesRegularExpression('/^#[0-9a-f]{6}$/', $c);
        }
        self::assertMatchesRegularExpression('/^tok_[0-9a-f]{12}$/', $p->fakeToken('x'));
        self::assertMatchesRegularExpression('/^[a-z]{2,3}-[0-9a-f]{4}$/', $p->classPrefix());
        self::assertContains(explode('-', $p->classPrefix())[0], PersonaIdentity::CLASS_PREFIX_WORDS);
    }

    /** The db.* accessors delegate to the wrapped PersonaIdentity — non-empty and, since the
     *  identity is a pure function of the seed, byte-identical across two instances of the same seed. */
    public function test_db_accessors_are_nonempty_and_deterministic_per_seed(): void
    {
        $a = VisualPersona::fromSeed(123);
        $b = VisualPersona::fromSeed(123);

        self::assertNotSame('', $a->dbHost());
        self::assertNotSame('', $a->dbName());
        self::assertNotSame('', $a->dbUser());
        self::assertNotSame('', $a->dbPassword());

        self::assertSame($a->dbHost(), $b->dbHost());
        self::assertSame($a->dbName(), $b->dbName());
        self::assertSame($a->dbUser(), $b->dbUser());
        self::assertSame($a->dbPassword(), $b->dbPassword());
    }

    public function test_db_accessors_diverge_across_seeds(): void
    {
        $x = VisualPersona::fromSeed(1);
        $y = VisualPersona::fromSeed(2);

        // Not every field is guaranteed to diverge for any two seeds (small dictionaries), but the
        // high-entropy password must, and it's enough to prove the accessor isn't a fixed constant.
        self::assertNotSame($x->dbPassword(), $y->dbPassword());
    }

    public function test_person_is_deterministic_per_seed_and_key(): void
    {
        $a = VisualPersona::fromSeed(123);
        $b = VisualPersona::fromSeed(123);
        self::assertSame($a->person('row-0'), $b->person('row-0'));
    }

    public function test_person_diverges_by_key(): void
    {
        $p = VisualPersona::fromSeed(123);
        self::assertNotSame($p->person('row-0'), $p->person('row-1'));
    }

    /** Coherence: personEmail must use THIS persona's company domain, not a fixed placeholder
     *  like example.com — a fake user table must never contradict the company shown elsewhere. */
    public function test_person_email_uses_persona_domain_not_example_com(): void
    {
        $p = VisualPersona::fromSeed(123);
        $domain = $p->domain();

        self::assertNotSame('example.com', $domain);
        self::assertStringEndsWith('@' . $domain, $p->personEmail('row-0'));
        self::assertSame($p->person('row-0')['userName'] . '@' . $domain, $p->personEmail('row-0'));
    }

    public function test_person_email_is_deterministic(): void
    {
        $a = VisualPersona::fromSeed(456);
        $b = VisualPersona::fromSeed(456);
        self::assertSame($a->personEmail('row-2'), $b->personEmail('row-2'));
    }

    public function test_person_job_title_and_city_are_deterministic_and_nonempty(): void
    {
        $a = VisualPersona::fromSeed(9);
        $b = VisualPersona::fromSeed(9);
        self::assertSame($a->personJobTitle('row-0'), $b->personJobTitle('row-0'));
        self::assertSame($a->personCity('row-0'), $b->personCity('row-0'));
        self::assertNotSame('', $a->personJobTitle('row-0'));
        self::assertNotSame('', $a->personCity('row-0'));
    }

    /** New capability: the wrapped PersonaIdentity is reachable so a skin can derive a coherent
     *  per-deploy product version without VisualPersona re-exposing every PersonaIdentity accessor. */
    public function test_identity_exposes_the_wrapped_persona_identity(): void
    {
        $p = VisualPersona::fromSeed(42);
        self::assertInstanceOf(PersonaIdentity::class, $p->identity());
        self::assertSame($p->domain(), $p->identity()->field('company.domain'));
    }

    /**
     * The class prefix is now a PersonaIdentity field, and VisualPersona delegates to it. For the whole
     * flow to read as one host, the value the login/gate templates resolve ({{persona.classPrefix}} ->
     * PersonaIdentity::field('classPrefix')) MUST equal the value the authed dashboard skin renders
     * (VisualPersona::classPrefix()). Sweep seeds and require byte-equality plus the shipped shape.
     */
    public function test_class_prefix_is_coherent_across_persona_and_visual_tiers(): void
    {
        for ($seed = 0; $seed < 40; $seed++) {
            $identityPrefix = PersonaIdentity::fromSeed($seed)->field('classPrefix');
            $visualPrefix = VisualPersona::fromSeed($seed)->classPrefix();
            self::assertNotNull($identityPrefix, "seed {$seed}: classPrefix field must exist");
            self::assertSame($identityPrefix, $visualPrefix, "seed {$seed}: login and dashboard prefixes must match");
            self::assertMatchesRegularExpression('/^[a-z]{2,3}-[0-9a-f]{4}$/', (string) $visualPrefix, "seed {$seed}: prefix shape");
        }
    }

    /**
     * FP-0283 DELIBERATELY moves the prefix WORD (the FP-0005 "shipped prefix must not move" invariant
     * is superseded on purpose — the funnypot-signature `fp-` is exactly what this ticket retires). But
     * the two independent halves stay pinned: the 4-hex TAIL keeps the historical `|visual|prefix`
     * derivation byte-for-byte (only the word moves off `fp-`), and the WORD is exactly the seed pick
     * from CLASS_PREFIX_WORDS. Assert both against their formulas so an accidental tail move is caught.
     */
    public function test_class_prefix_tail_is_the_historical_derivation_and_the_word_is_seed_picked(): void
    {
        for ($seed = 0; $seed < 40; $seed++) {
            $prefix = VisualPersona::fromSeed($seed)->classPrefix();
            [$word, $tail] = explode('-', $prefix);

            $expectedTail = substr(hash('sha256', $seed . '|visual|prefix'), 0, 4);
            self::assertSame($expectedTail, $tail, "seed {$seed}: the hex tail must not move from the historical derivation");

            $expectedWord = SubSeed::pick(PersonaIdentity::CLASS_PREFIX_WORDS, $seed, SubSeed::NS_VISUAL, 'prefix-word');
            self::assertSame($expectedWord, $word, "seed {$seed}: the word must be the seed pick from CLASS_PREFIX_WORDS");
            self::assertStringStartsNotWith('fp', $word, "seed {$seed}: the retired fp- signature must never reappear");
        }
    }

    /** Over many materials the word varies (not a fresh fleet constant) and the gate pair — the two
     *  surfaces the seeded-render gate's G4 compares — draws two different prefixes. */
    public function test_prefix_word_varies_and_never_reintroduces_fp(): void
    {
        $words = [];
        $materials = ['', 'funnypot', 'fp-0276-sample-a', 'fp-0276-sample-b'];
        for ($i = 0; $i < 60; $i++) {
            $materials[] = 'm-' . $i;
        }
        foreach ($materials as $m) {
            $prefix = VisualPersona::fromSeed(PersonaIdentity::seedFromMaterial($m))->classPrefix();
            self::assertStringStartsNotWith('fp-', $prefix, "material '{$m}': no fp- prefix");
            $words[explode('-', $prefix)[0]] = true;
        }
        self::assertGreaterThanOrEqual(8, count($words), 'the prefix word must vary widely across deploys');

        $a = VisualPersona::fromSeed(PersonaIdentity::seedFromMaterial('fp-0276-sample-a'))->classPrefix();
        $b = VisualPersona::fromSeed(PersonaIdentity::seedFromMaterial('fp-0276-sample-b'))->classPrefix();
        self::assertNotSame($a, $b, 'the gate pair must draw two different prefixes (G4 compares them)');
    }

    /**
     * FP-0283 seeded fg + muted into one coherent grey family. fg is a dark near-neutral (every channel
     * in [14,35]); muted is fg lifted by ONE per-deploy amount in [52,63] on all three channels; the
     * pair keeps ANALYTIC WCAG contrast floors — provable at EVERY seed, not just sampled — of fg/bg ≥ 7,
     * muted/bg ≥ 3, fg/muted ≥ 1.8 (worst analytic cases 8.46 / 3.28 / 1.92; today's fixed #6b7280
     * scored only 2.60 against the darkest bg). The old fixed pair (#1b1e21,#6b7280) may recur by chance
     * but at ≤ 0.5% of seeds. bg/accent/border keep their historical formulas byte-for-byte.
     */
    public function test_fg_and_muted_are_a_seeded_coherent_legible_grey_family(): void
    {
        $fgSet = [];
        $mutedSet = [];
        $legacyFg = 0;
        $legacyBoth = 0;
        $n = 500;
        for ($i = 0; $i < $n; $i++) {
            $seed = PersonaIdentity::seedFromMaterial('grey-' . $i);
            $pal = VisualPersona::fromSeed($seed)->palette();

            self::assertMatchesRegularExpression('/^#[0-9a-f]{6}$/', $pal['fg']);
            self::assertMatchesRegularExpression('/^#[0-9a-f]{6}$/', $pal['muted']);

            $fg = self::channels($pal['fg']);
            $muted = self::channels($pal['muted']);
            $lifts = [];
            for ($c = 0; $c < 3; $c++) {
                self::assertGreaterThanOrEqual(14, $fg[$c], "fg channel floor at grey-{$i}");
                self::assertLessThanOrEqual(35, $fg[$c], "fg channel ceiling at grey-{$i}");
                $lifts[] = $muted[$c] - $fg[$c];
            }
            // ONE lift on all three channels (muted keeps fg's tint), in [52,63].
            self::assertSame([$lifts[0], $lifts[0], $lifts[0]], $lifts, "muted must be fg + one uniform lift at grey-{$i}");
            self::assertGreaterThanOrEqual(52, $lifts[0], "lift floor at grey-{$i}");
            self::assertLessThanOrEqual(63, $lifts[0], "lift ceiling at grey-{$i}");

            self::assertGreaterThanOrEqual(7.0, self::contrast($pal['fg'], $pal['bg']), "fg/bg contrast at grey-{$i}");
            self::assertGreaterThanOrEqual(3.0, self::contrast($pal['muted'], $pal['bg']), "muted/bg contrast at grey-{$i}");
            self::assertGreaterThanOrEqual(1.8, self::contrast($pal['fg'], $pal['muted']), "fg/muted contrast at grey-{$i}");

            $fgSet[$pal['fg']] = true;
            $mutedSet[$pal['muted']] = true;
            if ($pal['fg'] === '#1b1e21') {
                $legacyFg++;
                if ($pal['muted'] === '#6b7280') {
                    $legacyBoth++;
                }
            }
        }
        self::assertGreaterThanOrEqual(300, count($fgSet), 'fg must not collapse to few values');
        self::assertGreaterThanOrEqual(300, count($mutedSet), 'muted must not collapse to few values');
        self::assertLessThanOrEqual($n * 0.005, $legacyFg, 'the legacy fixed fg must be rare, not the constant it was');
        self::assertSame(0, $legacyBoth, 'the legacy fixed fg+muted pair must never recur together');
    }

    /** bg/accent/border are UNTOUCHED by FP-0283 — assert byte-identity to their historical formulas so
     *  the palette move is scoped to exactly fg + muted. */
    public function test_bg_accent_border_are_unchanged_from_historical_formulas(): void
    {
        for ($seed = 0; $seed < 40; $seed++) {
            $pal = VisualPersona::fromSeed($seed)->palette();
            $bgHex = hash('sha256', $seed . '|visual|bg');
            $borderHex = hash('sha256', $seed . '|visual|border');
            self::assertSame('#' . self::light($bgHex), $pal['bg'], "bg must not move at seed {$seed}");
            self::assertSame('#' . self::light($borderHex), $pal['border'], "border must not move at seed {$seed}");
            self::assertSame('#' . substr(hash('sha256', $seed . '|visual|accent'), 0, 6), $pal['accent'], "accent must not move at seed {$seed}");
        }
    }

    /** The classPrefix field is populated unconditionally, so fromSeed() is total — the fail-closed
     *  LogicException branch is dead on the shipped identity (never thrown for any real seed). */
    public function test_from_seed_never_throws_over_many_seeds(): void
    {
        for ($seed = 0; $seed < 40; $seed++) {
            VisualPersona::fromSeed($seed);
        }
        self::assertTrue(true);
    }

    /** @return array{0:int,1:int,2:int} the three channel byte values of a #rrggbb hex */
    private static function channels(string $hex): array
    {
        $hex = ltrim($hex, '#');
        return [hexdec(substr($hex, 0, 2)), hexdec(substr($hex, 2, 2)), hexdec(substr($hex, 4, 2))];
    }

    /** The light() formula, mirrored here so the bg/border regression lock is self-contained. */
    private static function light(string $hex): string
    {
        $out = '';
        for ($i = 0; $i < 3; $i++) {
            $b = hexdec(substr($hex, $i * 2, 2)) % 64 + 190;
            $out .= str_pad(dechex($b), 2, '0', STR_PAD_LEFT);
        }
        return $out;
    }

    /** WCAG 2.x relative-luminance contrast ratio between two #rrggbb hex colors. */
    private static function contrast(string $a, string $b): float
    {
        $la = self::luminance($a);
        $lb = self::luminance($b);
        $hi = max($la, $lb);
        $lo = min($la, $lb);
        return ($hi + 0.05) / ($lo + 0.05);
    }

    private static function luminance(string $hex): float
    {
        $ch = self::channels($hex);
        $lin = [];
        foreach ($ch as $v) {
            $s = $v / 255.0;
            $lin[] = $s <= 0.03928 ? $s / 12.92 : (($s + 0.055) / 1.055) ** 2.4;
        }
        return 0.2126 * $lin[0] + 0.7152 * $lin[1] + 0.0722 * $lin[2];
    }
}
