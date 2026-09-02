<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

/**
 * Classifies a deploy's seed material and reports whether the install is safely de-fingerprinted
 * (FP-0276, the "material guarantee"). GUARD-AND-WARN, never re-derive: this is a NON-SERVED health
 * signal computed by MATERIAL-STRING comparison only. It NEVER inspects the derived seed value and
 * NEVER changes a derivation — the derivation (PersonaIdentity::seedFromMaterial / Config::deploySeed)
 * is a byte-pinned cross-tier core/app contract, and re-rolling it on a live host would desync every
 * persona/fake/visual across an upgrade (the exact catastrophe the guard-and-warn decision forbids).
 *
 * Two INDEPENDENT conditions, because they drive two independent consumers:
 *   - identity material — what deploySeed() hashes (deploySeed if non-empty, else seedSalt). Drives
 *     {{persona.*}}, VisualPersona, the decoy-session identity, the beacon token.
 *   - render salt — seedSalt alone, the only per-deploy input of Config::seedFor(). Drives {{fake.*}},
 *     {{pick:}}, PersonaSelector, AbstractEmulator::pick. A deploy with deploySeed set but
 *     seedSalt === '' (the app-tier shape) has a seeded IDENTITY and an unsalted RENDER seed.
 *
 * Detection is a closed string test only — `=== ''` and a closed PLACEHOLDER_MATERIALS list. No
 * entropy or length heuristics (they would false-positive a legitimately short per-install secret).
 *
 * Pure, final, static; PHP 7.3-safe.
 */
final class SeedHealth
{
    public const IDENTITY_SET = 'set';
    public const IDENTITY_EMPTY = 'empty';
    public const IDENTITY_PLACEHOLDER = 'placeholder';

    public const RENDER_SALT_SET = 'set';
    public const RENDER_SALT_EMPTY = 'empty';

    /**
     * Materials a tier is KNOWN to ship as a default, reported as IDENTITY_PLACEHOLDER (distinct from
     * IDENTITY_EMPTY). Compared by string equality on the MATERIAL — NEVER by comparing derived seeds.
     * 'funnypot' is the app-tier default (funnypot-app AppConfig / SipConfig): every unconfigured
     * app+SIP deploy hashes it into ONE fleet-wide persona identity, so surfacing it here is the
     * truthful answer rather than calling the fleet default "seeded". Kept tiny and documented; the
     * app-side follow-up removes the default at its source.
     */
    private const PLACEHOLDER_MATERIALS = ['funnypot'];

    private function __construct()
    {
    }

    /**
     * @return array{identity:string,render_salt:string,ok:bool,warnings:list<string>} 'ok' is true iff
     *         identity is SET and render_salt is SET. Warnings are fixed operator-facing strings.
     */
    public static function evaluate(string $identityMaterial, string $renderSalt): array
    {
        $warnings = [];

        if ($identityMaterial === '') {
            $identity = self::IDENTITY_EMPTY;
            $warnings[] = 'identity material is empty: every unconfigured deploy shares one persona '
                . 'identity (set Config::$deploySeed or $seedSalt from a per-install secret)';
        } elseif (in_array($identityMaterial, self::PLACEHOLDER_MATERIALS, true)) {
            $identity = self::IDENTITY_PLACEHOLDER;
            $warnings[] = "identity material is a known placeholder ('" . $identityMaterial . "'): every "
                . 'deploy left on this default shares one persona identity (set Config::$deploySeed or '
                . '$seedSalt from a per-install secret)';
        } else {
            $identity = self::IDENTITY_SET;
        }

        if ($renderSalt === '') {
            $renderSaltState = self::RENDER_SALT_EMPTY;
            $warnings[] = "seedSalt is empty: the per-request render seed is crc32(Host|''), so "
                . '{{fake.*}} values are equalizable across deploys (set Config::$seedSalt from a '
                . 'per-install secret)';
        } else {
            $renderSaltState = self::RENDER_SALT_SET;
        }

        return [
            'identity' => $identity,
            'render_salt' => $renderSaltState,
            'ok' => $identity === self::IDENTITY_SET && $renderSaltState === self::RENDER_SALT_SET,
            'warnings' => $warnings,
        ];
    }
}
