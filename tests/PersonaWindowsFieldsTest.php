<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;

/**
 * FP-0389: the six additive persona `windows.*` fields (the canary Active-Directory identity leaked by
 * the NTLM Type-2). Pins: non-empty + deterministic per seed, distinct across deploys, NetBIOS shape,
 * dnsComputer coherence with dnsDomain, denylist-safety, and that the closed `persona.*` directive set
 * now resolves the new keys.
 */
final class PersonaWindowsFieldsTest extends TestCase
{
    private const KEYS = [
        'windows.netbiosDomain', 'windows.netbiosComputer', 'windows.dnsDomain',
        'windows.dnsComputer', 'windows.dnsForest', 'windows.osBuild',
    ];

    public function test_all_fields_non_empty_and_deterministic_per_seed(): void
    {
        foreach ([1, 42, 777] as $seed) {
            $a = PersonaIdentity::fromSeed($seed);
            $b = PersonaIdentity::fromSeed($seed);
            foreach (self::KEYS as $k) {
                self::assertNotSame('', (string) $a->field($k), "{$k} non-empty for seed {$seed}");
                self::assertSame($a->field($k), $b->field($k), "{$k} deterministic for seed {$seed}");
            }
        }
    }

    public function test_fields_are_distinct_across_seeds(): void
    {
        $domains = [];
        foreach ([1, 2, 3, 4, 5] as $seed) {
            $domains[] = PersonaIdentity::fromSeed($seed)->field('windows.dnsDomain');
        }
        // No fleet-wide constant: at least three distinct AD domains across five deploys.
        self::assertGreaterThanOrEqual(3, count(array_unique($domains)), 'dnsDomain must vary per deploy');
    }

    public function test_netbios_shape_and_dns_coherence(): void
    {
        foreach (range(1, 50) as $seed) {
            $p = PersonaIdentity::fromSeed($seed);
            $nbDomain = (string) $p->field('windows.netbiosDomain');
            $nbComputer = (string) $p->field('windows.netbiosComputer');
            $dnsDomain = (string) $p->field('windows.dnsDomain');
            $dnsComputer = (string) $p->field('windows.dnsComputer');
            $dnsForest = (string) $p->field('windows.dnsForest');

            self::assertLessThanOrEqual(15, strlen($nbDomain), "NetBIOS domain <=15 (seed {$seed})");
            self::assertSame(1, preg_match('/^[A-Z0-9]+$/', $nbDomain), "NetBIOS domain [A-Z0-9] (seed {$seed})");
            self::assertLessThanOrEqual(15, strlen($nbComputer), "NetBIOS computer <=15 (seed {$seed})");
            self::assertSame(1, preg_match('/^[A-Z0-9]+$/', $nbComputer), "NetBIOS computer [A-Z0-9] (seed {$seed})");

            // dnsComputer is the computer host under the AD DNS domain.
            self::assertStringEndsWith('.' . $dnsDomain, $dnsComputer, "dnsComputer under dnsDomain (seed {$seed})");
            self::assertStringStartsWith(strtolower($nbComputer) . '.', $dnsComputer, "dnsComputer host (seed {$seed})");
            // dnsForest is the domain itself or its registrable parent (always a suffix of dnsDomain).
            self::assertStringEndsWith($dnsForest, $dnsDomain, "dnsForest is a suffix of dnsDomain (seed {$seed})");
        }
    }

    public function test_no_field_trips_the_denied_digit_run(): void
    {
        foreach (range(1, 300) as $seed) {
            $p = PersonaIdentity::fromSeed($seed);
            foreach (self::KEYS as $k) {
                self::assertFalse(
                    SubSeed::hitsDeniedDigits((string) $p->field($k)),
                    "{$k} tripped the denied digit run (seed {$seed})"
                );
            }
        }
    }

    public function test_persona_directive_resolves_the_new_keys(): void
    {
        // The closed persona.* directive set must now accept windows.* — a {{persona.windows.dnsDomain}}
        // renders to the same value field() returns for the deploy seed.
        $seed = 123;
        $renderer = new DirectiveRenderer($seed);
        $out = $renderer->render('{{persona.windows.dnsDomain}}', [], $seed, []);
        self::assertSame(PersonaIdentity::fromSeed($seed)->field('windows.dnsDomain'), $out);
        self::assertNotSame('', $out);
    }
}
