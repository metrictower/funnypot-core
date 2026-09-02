<?php

declare(strict_types=1);

namespace Funnypot\Core\Synthesis;

use Funnypot\Core\Support\SubSeed;

/**
 * The per-deploy scaffold for minimal synthesis (FP-0281): the ONE place that derives the two
 * render-time bytes ResponseSynthesizer used to ship as fleet constants —
 *
 *   1. the ORDER of the `bw` (part:body word) list joined into a minimal-synth body, and
 *   2. the NAMES of the synthetic witness headers that used to be a self-identifying `X-Detected-N`.
 *
 * WHAT IS LOAD-BEARING vs INCIDENTAL. nuclei's `part: body`/`part: header` matchers (and funnypot's
 * own BundleValidator) test each `bw`/`hw` string as a SUBSTRING of the body / of the
 * "Key: value\n"-joined header block — never by position and never by header NAME. So the load-bearing
 * bytes are each word's PRESENCE and each witness header's VALUE (untouched by this class); the word
 * ORDER and the header NAME are incidental and are what vary per deploy. Permuting the `bw` words
 * cannot break a `contains` match, and the `\n` join is kept so distinct words never fuse and no `nf`
 * forbidden substring (0/370 of which contain LF in the shipped index) can form across a boundary;
 * renaming a witness header leaves its value — and therefore the header-block substring — intact.
 *
 * POOL HYGIENE (the marker-safety proof for the header names). The 112 composite names `X-<First>-<Suffix>`
 * are hand-curated so that, over the shipped nuclei index, NONE: contains any `hf` forbidden
 * header-block substring (case-insensitively); equals a typed-header (`th`) name or a chrome/reserved
 * name (RESERVED below); is a superstring of any `hw` witness word (so a seeded name can neither break
 * nor spuriously over-satisfy a header matcher); carries a fingerprint-denylist token or a bare CRS
 * digit; or carries CR/LF/NUL. Every name is already Go-canonical. Names deliberately avoid real CDN /
 * correlation header families (`goog`, `xss`, `cloudflare`, `cache`, `Request`, `Content`, `Cookie`).
 * SynthScaffoldTest re-runs every one of these checks against the live index so a future pool edit
 * cannot regress them.
 *
 * DETERMINISM / 32-BIT SAFETY. Every varied byte is a pure function of the deploy identity seed via
 * SubSeed::permute/pick under NS_SCAFFOLD only — never SubSeed::int (which is 64-bit-only), never a
 * clock/CSPRNG/request byte. Field registry (a field is never reused for a second purpose):
 * `body|order|<words>` (body permutation, keyed on the word list so each bundle draws independently),
 * `hdr|suffix` (the deploy's one witness-name suffix), `hdr|order` (the deploy's first-part order).
 *
 * PHP 7.3-safe: class constants, static methods, foreach only.
 */
final class SynthScaffold
{
    /**
     * The first parts of a witness-header name `X-<First>-<Suffix>`. Semantics-free, vendor-ish, and
     * screened against the shipped index (see class docblock + SynthScaffoldTest). 14 first parts cover
     * the corpus maximum of 5 witnesses per bundle with headroom.
     */
    public const NAME_FIRST = [
        'Upstream', 'Backend', 'Origin', 'Edge', 'Route', 'Svc', 'Pool',
        'Node', 'Env', 'Runtime', 'Cluster', 'Tier', 'Shard', 'Trace',
    ];

    /** The suffixes; one is picked per deploy so a host presents ONE coherent header vocabulary. */
    public const NAME_SUFFIX = ['Tag', 'Ref', 'Hint', 'Meta', 'Ctx', 'Key', 'Info', 'Scope'];

    /**
     * Header names a synthetic witness header must never shadow — typed-header and chrome names the
     * validator or nuclei match by NAME. The pool is disjoint from this list by construction; the
     * runtime assignment additionally skips any already-set key.
     */
    public const RESERVED = [
        'Content-Type', 'Content-Length', 'Server', 'X-Powered-By', 'X-Request-Id',
        'Set-Cookie', 'Location', 'Accept-Ranges', 'Content-Disposition', 'WWW-Authenticate',
    ];

    private function __construct()
    {
    }

    /**
     * The `bw` words in this deploy's order. A seeded Fisher-Yates permutation keyed on the word list
     * itself, so every bundle draws an INDEPENDENT order (a fixed field would apply one shape to every
     * same-length bundle on a deploy). Unchanged for a list of fewer than two items — a single-word
     * minimal-synth body IS its matcher and stays fleet-constant by nature (no bytes are invented).
     * A permutation of a `contains`-matched list can never break a matcher.
     *
     * @param list<string> $words
     * @return list<string> a permutation of $words (same multiset, same count)
     */
    public static function bodyOrder(array $words, int $seed): array
    {
        $words = array_values($words);

        return SubSeed::permute($words, $seed, SubSeed::NS_SCAFFOLD, 'body|order|' . implode("\x00", $words));
    }

    /**
     * The deploy's 14 witness-header names, in the deploy's order: one suffix picked per deploy +
     * a per-deploy permutation of the first parts. Coherent per deploy (one vocabulary, one host) and
     * varying across deploys (1-of-112 first name per deploy). The N-th still-missing witness takes the
     * N-th usable name — NO numeric ordinal (a `-1`/`-2` tail is itself a shape tell).
     *
     * @return list<string> 14 canonical `X-<First>-<Suffix>` names
     */
    public static function witnessHeaderNames(int $seed): array
    {
        $suffix = SubSeed::pick(self::NAME_SUFFIX, $seed, SubSeed::NS_SCAFFOLD, 'hdr|suffix');
        $firsts = SubSeed::permute(self::NAME_FIRST, $seed, SubSeed::NS_SCAFFOLD, 'hdr|order');

        $names = [];
        foreach ($firsts as $first) {
            $names[] = 'X-' . $first . '-' . $suffix;
        }

        return $names;
    }

    /**
     * Every possible pool name (112) — for the hygiene tests, never for serving.
     *
     * @return list<string>
     */
    public static function allNames(): array
    {
        $names = [];
        foreach (self::NAME_FIRST as $first) {
            foreach (self::NAME_SUFFIX as $suffix) {
                $names[] = 'X-' . $first . '-' . $suffix;
            }
        }

        return $names;
    }
}
