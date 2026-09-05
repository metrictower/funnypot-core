<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

/**
 * The one deploy-seed sub-derivation primitive (FP-0276), foundational for the de-fingerprinting
 * epic (FP-0277..FP-0284). It gives every deploy-seeded surface ONE domain-separated,
 * determinism-safe way to derive per-field values from a persona seed, so no two siblings hand-roll
 * a `hash('sha256', $seed.'|...|'.$field)` line that could silently drift or collide.
 *
 * BYTE-IDENTITY (the load-bearing invariant). digest()/index()/chars() reproduce, byte-for-byte, the
 * three inline deploy-seed derivations that already ship, so migrating those call sites to this class
 * is a no-op on served bytes:
 *   - PersonaIdentity::h()      `hash('sha256', $seed.'|persona|'.$field)`     == digest($seed, NS_PERSONA, $field)
 *   - DirectiveRenderer fake    `hash('sha256', $seed.'|fake|'.$name)`         == digest($seed, NS_FAKE, $name)
 *   - VisualPersona::hashFor()  `hash('sha256', $seed.'|visual|'.$field)`      == digest($seed, NS_VISUAL, $field)
 *   - PersonaIdentity::pick()   `hexdec(substr(h,0,8)) % n`                     == index($seed, NS_PERSONA, $field, n)
 *   - VisualPersona::pick()     `hexdec(substr('...|pick|'.$salt,0,8)) % n`     == index($seed, 'pick', $salt, n)
 *   - PersonaIdentity re-rolls  round tag `$field.'|r'.$round`                  == reroll()'s round tagging
 *
 * DOMAIN SEPARATION. A namespace (NS_*) is a `|`-delimited middle segment; it MUST NOT itself contain
 * a `|`. Two derivations that differ only in their namespace can never collide on one seed. New
 * surfaces claim a reserved NS_* below; a `'|<ns>|'` tag not registered here is caught by the
 * NS-registry lint (tests/SubSeedTest).
 *
 * WIDTH SAFETY. index()/chars() reduce with the FP-0260 SeededIndex fmod technique (SeededIndex::
 * fromHex), so a 32-bit PHP computes the SAME offset a 64-bit does instead of overflowing — and on
 * 64-bit the result is byte-identical to the `hexdec % n` the shipped sites use today. int() is the
 * one exception: it takes 15 hex (a 60-bit value, matching PersonaIdentity::seedFromMaterial's
 * width) and is therefore 64-bit-ONLY, exactly like seedFromMaterial — it must not be used to derive
 * a served offset on a 32-bit build. Range sugar (e.g. `$lo + index(..., $hi - $lo + 1)`) is a helper
 * a sibling can add; index() is the 32-bit-safe reduction to build it on.
 *
 * PURE. Every method is a pure function of its arguments — no clock, counter, CSPRNG, request byte, or
 * static state can enter (the signatures admit none). This is what the seeded-render gate's
 * render-twice determinism check relies on across the whole sub-seeded corpus.
 *
 * PHP 7.3-safe: hash()/hexdec()/substr()/fmod()/preg_match() only.
 */
final class SubSeed
{
    // Namespace registry — reserved, documented; a namespace never contains '|'.
    public const NS_PERSONA = 'persona';    // PersonaIdentity (existing bytes)
    public const NS_FAKE = 'fake';          // DirectiveRenderer {{fake.*}} (existing bytes; render-seed keyed)
    public const NS_VISUAL = 'visual';      // VisualPersona palette/prefix (existing bytes)
    public const NS_CANNED = 'canned';      // FP-0277
    public const NS_SURFACE = 'surface';    // FP-0278 (sitemap/robots/nouns coherence set)
    public const NS_ATTACK = 'attack';      // FP-0279 (attack-class body variants)
    public const NS_WITNESS = 'witness';    // FP-0280 (menu pick per pattern hash)
    public const NS_SCAFFOLD = 'scaffold';  // FP-0281 (minimal-synth order, header-name pick)
    public const NS_HONEYTOKEN = 'honeytoken'; // FP-0282
    public const NS_DECOY = 'decoy';        // FP-0282
    public const NS_REACTION = 'reaction';  // FP-0157 (param-reaction closed-family cosmetics)

    private function __construct()
    {
    }

    /**
     * 64-hex sha256 digest of the (seed, namespace, field) triple. The canonical sub-derivation:
     * `hash('sha256', $seed . '|' . $ns . '|' . $field)`. Byte-identical to PersonaIdentity::h()
     * (NS_PERSONA), DirectiveRenderer's `|fake|` (NS_FAKE), and VisualPersona::hashFor() (NS_VISUAL).
     */
    public static function digest(int $seed, string $ns, string $field): string
    {
        return hash('sha256', $seed . '|' . $ns . '|' . $field);
    }

    /**
     * A 60-bit child seed for handing a NEW seeded generator its own int seed:
     * `(int) hexdec(substr(digest, 0, 15))` — the same width/derivation SHAPE as
     * PersonaIdentity::seedFromMaterial. 64-bit-ONLY (15 hex overflows a 32-bit int), like
     * seedFromMaterial; never use it to derive a served array offset — use index() for that.
     */
    public static function int(int $seed, string $ns, string $field): int
    {
        return (int) hexdec(substr(self::digest($seed, $ns, $field), 0, 15));
    }

    /**
     * A stable offset in [0, $count): the first 8 hex of digest() reduced mod $count. On 64-bit this
     * is byte-identical to `hexdec(substr(digest, 0, 8)) % $count` (PersonaIdentity::pick /
     * VisualPersona::pick); the reduction goes through SeededIndex::fromHex so 32-bit PHP agrees
     * instead of overflowing. Returns 0 for $count < 1.
     */
    public static function index(int $seed, string $ns, string $field, int $count): int
    {
        return SeededIndex::fromHex(substr(self::digest($seed, $ns, $field), 0, 8), $count);
    }

    /**
     * $options[index(...)]. '' on an empty list.
     *
     * @param list<string> $options
     */
    public static function pick(array $options, int $seed, string $ns, string $field): string
    {
        if ($options === []) {
            return '';
        }

        return $options[self::index($seed, $ns, $field, count($options))];
    }

    /**
     * A seeded Fisher-Yates permutation of $items, driven by successive 4-hex windows of digest();
     * when the 64 hex chars of one digest are exhausted it continues with digest(field.'|p'.N). Pure
     * and stable per (seed, ns, field). A single-element or empty list is returned unchanged.
     *
     * @param list<mixed> $items
     * @return list<mixed>
     */
    public static function permute(array $items, int $seed, string $ns, string $field): array
    {
        $items = array_values($items);
        $n = count($items);
        if ($n < 2) {
            return $items;
        }

        $hex = self::digest($seed, $ns, $field);
        $pos = 0;
        $block = 0;
        // Fisher-Yates from the high index down; each step draws a fresh 4-hex window (0..65535)
        // and reduces it into [0, i] via the same fmod reduction index() uses (32-bit-safe).
        for ($i = $n - 1; $i > 0; $i--) {
            if ($pos + 4 > strlen($hex)) {
                $block++;
                $hex = self::digest($seed, $ns, $field . '|p' . $block);
                $pos = 0;
            }
            $window = substr($hex, $pos, 4);
            $pos += 4;
            $j = SeededIndex::fromHex($window, $i + 1);
            $tmp = $items[$i];
            $items[$i] = $items[$j];
            $items[$j] = $tmp;
        }

        return $items;
    }

    /**
     * The first $k of permute() — a seeded subset. $k is clamped to [0, count].
     *
     * @param list<mixed> $items
     * @return list<mixed>
     */
    public static function subset(array $items, int $k, int $seed, string $ns, string $field): array
    {
        if ($k <= 0) {
            return [];
        }
        $permuted = self::permute($items, $seed, $ns, $field);
        if ($k >= count($permuted)) {
            return $permuted;
        }

        return array_slice($permuted, 0, $k);
    }

    /**
     * An alphabet-mapped string of $length, each output char drawn from one digest byte
     * (`$alphabet[hexdec(2 hex) % strlen($alphabet)]`). One digest covers 32 chars; a longer run
     * chains digest(field.'|c'.N). Byte-identical to PersonaIdentity::password()'s inner loop for
     * length <= 32. Returns '' for a non-positive length or an empty alphabet.
     */
    public static function chars(int $seed, string $ns, string $field, string $alphabet, int $length): string
    {
        $alphabetLen = strlen($alphabet);
        if ($length <= 0 || $alphabetLen === 0) {
            return '';
        }
        $out = '';
        $block = 0;
        while (strlen($out) < $length) {
            $h = $block === 0 ? self::digest($seed, $ns, $field) : self::digest($seed, $ns, $field . '|c' . $block);
            for ($i = 0; $i < 64 && strlen($out) < $length; $i += 2) {
                $out .= $alphabet[hexdec(substr($h, $i, 2)) % $alphabetLen];
            }
            $block++;
        }

        return $out;
    }

    /**
     * The denied-token re-roll loop, generalized. Calls $gen($round === 0 ? $field : $field.'|r'.$round)
     * until !$reject(value); the round tagging is byte-identical to the re-roll loops in
     * PersonaIdentity (password/awsSecretKey/googleApiKey/nextBuildId) and FakeSecrets. The default
     * $reject is hitsDeniedDigits. $maxRounds bounds the loop (a pathological $reject that never
     * accepts throws a RuntimeException rather than spinning forever).
     *
     * @param callable(string):string $gen    given the round-tagged field, returns a candidate value
     * @param (callable(string):bool)|null $reject true ⇒ re-roll; null ⇒ hitsDeniedDigits
     */
    public static function reroll(string $field, callable $gen, ?callable $reject = null, int $maxRounds = 64): string
    {
        if ($reject === null) {
            $reject = [self::class, 'hitsDeniedDigits'];
        }
        for ($round = 0; $round <= $maxRounds; $round++) {
            $value = $gen($round === 0 ? $field : $field . '|r' . $round);
            if (!$reject($value)) {
                return $value;
            }
        }

        throw new \RuntimeException('SubSeed::reroll exhausted ' . $maxRounds . ' rounds for field "' . $field . '"');
    }

    /**
     * True if a value carries the fingerprint gate's denied bare-6-digit token (`\b9\d{5}\b`, a bare
     * CRS rule id — resources/fingerprint-denylist.php). The ONE definition of this predicate;
     * PersonaIdentity::hitsDeniedDigits and FakeSecrets::hitsDeniedDigits delegate here. A test pins
     * this literal to the denylist entry so the gate and the generators can never disagree.
     */
    public static function hitsDeniedDigits(string $value): bool
    {
        return preg_match('/\b9\d{5}\b/', $value) === 1;
    }
}
