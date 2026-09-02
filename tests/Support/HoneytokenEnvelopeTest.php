<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Support;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\HoneytokenEnvelope;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * HoneytokenEnvelope (FP-0282) seeds the bait cookie NAME, `key=role` payload vocabulary, and attribute
 * tail per deploy — the envelope around the load-bearing HMAC value. These tests pin the contract and
 * the hygiene rules that keep the envelope from being a new tell or from clobbering another cookie:
 *  - names are session-cookie-shaped, cookie-token chars only (no '.'), fingerprint-clean, and DISJOINT
 *    from every name another tier plants (route set_cookie: names + the decoy-session names);
 *  - the payload always names a LOW role (the escalation bait) — never an admin/root/super class word;
 *  - the attribute tail is a shape a real PHP stack emits (HttpOnly always, Secure never, path=/ the one
 *    substitution point);
 *  - it is a pure function of the deploy seed (stable within a deploy, varying across).
 *
 * Every assertion fails at baseline `1ac81d3` (the class did not exist).
 */
final class HoneytokenEnvelopeTest extends TestCase
{
    /** @return list<int> */
    private function seeds(): array
    {
        $seeds = [
            PersonaIdentity::seedFromMaterial(''),
            PersonaIdentity::seedFromMaterial('funnypot'),
            PersonaIdentity::seedFromMaterial('fp-0276-sample-a'),
            PersonaIdentity::seedFromMaterial('fp-0276-sample-b'),
        ];
        for ($i = 0; $i < 60; $i++) {
            $seeds[] = PersonaIdentity::seedFromMaterial('m-' . $i);
        }

        return $seeds;
    }

    // --- contract ---------------------------------------------------------------------------

    public function test_name_payload_and_attributes_shape(): void
    {
        foreach ($this->seeds() as $seed) {
            self::assertContains(HoneytokenEnvelope::name($seed), HoneytokenEnvelope::NAMES);

            self::assertMatchesRegularExpression(
                '/^[a-z]+=(user|member|std|basic|guest|viewer)$/',
                HoneytokenEnvelope::payload($seed),
                'payload must be a low-role key=role pair'
            );

            $attr = HoneytokenEnvelope::attributes($seed);
            self::assertStringStartsWith('; path=/; ', $attr);
            self::assertStringContainsStringIgnoringCase('httponly', $attr, 'HttpOnly must always be present');
            self::assertStringNotContainsStringIgnoringCase('secure', $attr, 'Secure must never be present (an http deploy sending it is a tell)');
            self::assertStringNotContainsString(';;', $attr);
            foreach (["\r", "\n", "\0"] as $ctl) {
                self::assertStringNotContainsString($ctl, $attr, 'no control byte in the attribute tail');
            }
        }
    }

    public function test_attributes_substitute_the_path_exactly_once(): void
    {
        foreach ($this->seeds() as $seed) {
            $scoped = HoneytokenEnvelope::attributes($seed, '/app');
            self::assertStringContainsString('path=/app', $scoped);
            self::assertSame(1, substr_count($scoped, 'path='), 'the path attribute appears exactly once');
            // The default is the root scope.
            self::assertStringContainsString('path=/;', HoneytokenEnvelope::attributes($seed) . ';');
        }
    }

    public function test_within_deploy_stable_across_deploy_varying(): void
    {
        $seedA = PersonaIdentity::seedFromMaterial('fp-0276-sample-a');
        $seedB = PersonaIdentity::seedFromMaterial('fp-0276-sample-b');

        self::assertSame(HoneytokenEnvelope::name($seedA), HoneytokenEnvelope::name($seedA));
        self::assertSame(HoneytokenEnvelope::payload($seedA), HoneytokenEnvelope::payload($seedA));
        self::assertSame(HoneytokenEnvelope::attributes($seedA), HoneytokenEnvelope::attributes($seedA));

        // The two seeded-render gate materials draw different names (pins that G4 pin non-vacuous).
        self::assertNotSame(
            HoneytokenEnvelope::name($seedA),
            HoneytokenEnvelope::name($seedB),
            'the gate pair must draw different bait names'
        );
    }

    // --- hygiene ----------------------------------------------------------------------------

    public function test_names_are_cookie_token_clean_and_disjoint_from_other_planted_cookies(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $reserved = $this->otherPlantedCookieNames();

        foreach (HoneytokenEnvelope::NAMES as $name) {
            self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $name, 'no "." so $_COOKIE keys are verbatim: ' . $name);
            self::assertSame([], $guard->scan($name), 'a bait name must not carry a detector signature: ' . $name);
            self::assertArrayNotHasKey($name, $reserved, 'a bait name must not collide with another planted cookie: ' . $name);
            self::assertNotSame('', $name, 'a bait name must be non-empty');
            // Not in the decoy WordPress cookie family either.
            self::assertStringStartsNotWith('wordpress_logged_in_', $name);
        }
    }

    public function test_roles_are_low_privilege_only(): void
    {
        foreach (HoneytokenEnvelope::ROLES as $role) {
            foreach (['admin', 'root', 'super', 'owner'] as $high) {
                self::assertStringNotContainsString($high, $role, 'the lure must name a LOW role only: ' . $role);
            }
        }
    }

    public function test_attrs_pool_is_deduped(): void
    {
        // N1: the plan's duplicate SameSite=Lax entry is removed — the pool is 4 DISTINCT tails.
        self::assertCount(4, HoneytokenEnvelope::ATTRS);
        self::assertSame(HoneytokenEnvelope::ATTRS, array_values(array_unique(HoneytokenEnvelope::ATTRS)), 'ATTRS must have no duplicate entry');
    }

    // --- variance ---------------------------------------------------------------------------

    public function test_the_envelope_varies_widely_and_does_not_reproduce_the_old_constant(): void
    {
        $distinct = [];
        $reproduceToday = 0;
        $namesUsed = [];

        foreach ($this->seeds() as $seed) {
            $name = HoneytokenEnvelope::name($seed);
            $namesUsed[$name] = true;
            $envelope = $name . '|' . HoneytokenEnvelope::payload($seed) . '|' . HoneytokenEnvelope::attributes($seed);
            $distinct[$envelope] = true;
            // The old fleet constant was name 'sess', payload 'r=user', tail '; path=/; HttpOnly' (no SameSite).
            if ($name === 'sess'
                && HoneytokenEnvelope::payload($seed) === 'r=user'
                && HoneytokenEnvelope::attributes($seed) === '; path=/; HttpOnly') {
                $reproduceToday++;
            }
        }

        self::assertGreaterThanOrEqual(50, count($distinct), 'the bait envelope must vary widely across deploys');
        self::assertGreaterThanOrEqual(8, count($namesUsed), 'most of the name pool must be reachable');
        // Essentially unreachable (measured 0/64); a loose bound is robust to pool tuning.
        self::assertLessThanOrEqual(2, $reproduceToday, 'the old sess=r=user; path=/; HttpOnly constant must not be a common draw');
    }

    /**
     * The names every OTHER tier plants: the route templates' `set_cookie:` names (parsed at test time,
     * so a newly-added route cookie is caught) plus the two decoy-session product cookie names.
     *
     * @return array<string,true>
     */
    private function otherPlantedCookieNames(): array
    {
        $names = ['phpMyAdmin' => true];
        $dir = dirname(__DIR__, 2) . '/templates/route';
        foreach ((array) glob($dir . '/*.yaml') as $file) {
            $src = (string) file_get_contents((string) $file);
            if (preg_match_all('/^\s*set_cookie:\s*(\S+)\s*$/m', $src, $m) && isset($m[1])) {
                foreach ($m[1] as $name) {
                    $names[$name] = true;
                }
            }
        }
        self::assertGreaterThanOrEqual(8, count($names), 'the route set_cookie: parse must find the known cookie names');

        return $names;
    }
}
