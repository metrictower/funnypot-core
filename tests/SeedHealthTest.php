<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\HealthObserver;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SeedHealth;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * FP-0276 material guarantee. The seed-health signal detects an unseeded/fleet-constant install from
 * the MATERIAL STRING and warns — it NEVER re-derives and NEVER enters a served byte. These tests pin:
 * the classification states; that Config::deploySeed() output is byte-unchanged for '' and 'funnypot'
 * (guard-and-warn, not re-roll); that the report never reaches SynthesizedResponse; and the
 * push/pull delivery contract.
 */
final class SeedHealthTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                't-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A'],
            ],
            'routes' => [
                'GET /multi' => ['b' => [
                    ['s' => 200, 'bw' => ['AAA'], 'nf' => [], 'h' => [], 'pid' => 'pa', 'sev' => 'low', 'sig' => 0, 't' => ['t-a']],
                ]],
            ],
        ]);
    }

    /**
     * Served headers minus the per-request X-Request-Id (E1) — the one legitimate per-request variance
     * on the respond() facade, unrelated to the seed-health signal under test.
     *
     * @param array<string,string|string[]> $headers
     * @return array<string,string|string[]>
     */
    private function stableHeaders(array $headers): array
    {
        unset($headers['X-Request-Id']);

        return $headers;
    }

    private function respondConfig(Config $c): Config
    {
        $c->mode = 'respond';
        $c->gate = static function (RequestContext $r): bool { return true; };
        $c->responseStyle = Style::MINIMAL;

        return $c;
    }

    // --- (a) unseeded install ---------------------------------------------------------------------

    public function test_default_config_is_empty_identity_and_empty_render_salt(): void
    {
        $health = (new Config())->seedHealth();
        self::assertSame(SeedHealth::IDENTITY_EMPTY, $health['identity']);
        self::assertSame(SeedHealth::RENDER_SALT_EMPTY, $health['render_salt']);
        self::assertFalse($health['ok']);
        self::assertCount(2, $health['warnings']);
    }

    /**
     * The fleet-default seed is DELIBERATELY unchanged and fleet-constant: guard-and-warn NEVER
     * re-derives. This value is seedFromMaterial(''); a future "fix" of the empty case that changed it
     * would re-roll every unconfigured deploy's identity on upgrade, and must fail here.
     */
    public function test_deploy_seed_output_is_unchanged_for_the_empty_material(): void
    {
        self::assertSame(67142204528030646, (new Config())->deploySeed());
        self::assertSame(PersonaIdentity::seedFromMaterial(''), (new Config())->deploySeed());
    }

    // --- (b) placeholder + app-tier shape + healthy ----------------------------------------------

    public function test_known_placeholder_material_is_reported_distinctly_and_not_re_derived(): void
    {
        $c = new Config();
        $c->deploySeed = 'funnypot';
        $health = $c->seedHealth();
        self::assertSame(SeedHealth::IDENTITY_PLACEHOLDER, $health['identity']);
        self::assertFalse($health['ok']);
        // deploySeed() output is byte-unchanged — the placeholder is only a WARNING, never a re-derive.
        self::assertSame(PersonaIdentity::seedFromMaterial('funnypot'), $c->deploySeed());
        self::assertSame(485359511181776946, $c->deploySeed());
    }

    public function test_app_tier_shape_is_seeded_identity_but_empty_render_salt(): void
    {
        $c = new Config();
        $c->deploySeed = 'a-per-install-secret';
        $c->seedSalt = '';
        $health = $c->seedHealth();
        self::assertSame(SeedHealth::IDENTITY_SET, $health['identity']);
        self::assertSame(SeedHealth::RENDER_SALT_EMPTY, $health['render_salt']);
        self::assertFalse($health['ok']);
        self::assertCount(1, $health['warnings']);
    }

    public function test_both_configured_is_ok_with_no_warnings(): void
    {
        $c = new Config();
        $c->deploySeed = 'identity-secret';
        $c->seedSalt = 'render-salt';
        $health = $c->seedHealth();
        self::assertSame(SeedHealth::IDENTITY_SET, $health['identity']);
        self::assertSame(SeedHealth::RENDER_SALT_SET, $health['render_salt']);
        self::assertTrue($health['ok']);
        self::assertSame([], $health['warnings']);
    }

    public function test_seed_salt_alone_seeds_both_identity_and_render(): void
    {
        // With no explicit deploySeed, seedSalt is the identity material AND the render salt.
        $c = new Config();
        $c->seedSalt = 'one-secret';
        $health = $c->seedHealth();
        self::assertSame(SeedHealth::IDENTITY_SET, $health['identity']);
        self::assertSame(SeedHealth::RENDER_SALT_SET, $health['render_salt']);
        self::assertTrue($health['ok']);
    }

    // --- evaluate() is material-only --------------------------------------------------------------

    public function test_evaluate_classifies_purely_by_material_string(): void
    {
        self::assertSame(SeedHealth::IDENTITY_EMPTY, SeedHealth::evaluate('', 'x')['identity']);
        self::assertSame(SeedHealth::IDENTITY_PLACEHOLDER, SeedHealth::evaluate('funnypot', 'x')['identity']);
        self::assertSame(SeedHealth::IDENTITY_SET, SeedHealth::evaluate('funnypot-x', 'x')['identity'], 'a superstring of the placeholder is NOT the placeholder');
        self::assertSame(SeedHealth::RENDER_SALT_SET, SeedHealth::evaluate('m', 'salt')['render_salt']);
        self::assertSame(SeedHealth::RENDER_SALT_EMPTY, SeedHealth::evaluate('m', '')['render_salt']);
    }

    // --- (c) never served -------------------------------------------------------------------------

    public function test_seed_health_is_never_a_served_byte(): void
    {
        $unseeded = new Honeypot($this->store(), $this->respondConfig(new Config()));
        $probe = new RequestContext('GET', '/multi');
        $baseline = $unseeded->respond($probe);
        self::assertNotNull($baseline);

        // The same deploy but with a HealthObserver attached serves byte-identical output.
        $withObserver = new Honeypot($this->store(), $this->respondConfig(new Config()), new class implements HealthObserver, Observer {
            /** @var array<string,mixed>|null */
            public $report;

            public function onSeedHealth(array $report): void
            {
                $this->report = $report;
            }

            public function onDetection(RequestContext $r, Detection $d): void
            {
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
            }
        });
        $observed = $withObserver->respond($probe);
        self::assertNotNull($observed);
        self::assertSame($baseline->status, $observed->status);
        self::assertSame($this->stableHeaders($baseline->headers), $this->stableHeaders($observed->headers));
        self::assertSame($baseline->body, $observed->body);

        // No served string carries any warning text.
        $served = $baseline->body . '|' . implode('|', array_map('strval', $baseline->headers));
        foreach ((new Config())->seedHealth()['warnings'] as $warning) {
            self::assertStringNotContainsString($warning, $served);
        }
        self::assertStringNotContainsString('fleet', $served);
        self::assertStringNotContainsString('placeholder', $served);
    }

    // --- (d) push / pull delivery -----------------------------------------------------------------

    public function test_push_fires_once_at_construction_with_the_same_array_as_pull(): void
    {
        $observer = new class implements HealthObserver, Observer {
            /** @var list<array<string,mixed>> */
            public $reports = [];

            public function onSeedHealth(array $report): void
            {
                $this->reports[] = $report;
            }

            public function onDetection(RequestContext $r, Detection $d): void
            {
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
            }
        };
        $config = $this->respondConfig(new Config());
        $honeypot = new Honeypot($this->store(), $config, $observer);

        self::assertCount(1, $observer->reports, 'push fires exactly once at construction');
        self::assertSame($config->seedHealth(), $observer->reports[0], 'push report equals the pull report');
        self::assertSame($config->seedHealth(), $honeypot->seedHealth(), 'Honeypot::seedHealth() is the pull companion');

        // respond() must not fire the push again.
        $honeypot->respond(new RequestContext('GET', '/multi'));
        self::assertCount(1, $observer->reports, 'respond() never re-fires the push');
    }

    public function test_a_throwing_health_observer_neither_escapes_nor_changes_bytes(): void
    {
        $baseline = (new Honeypot($this->store(), $this->respondConfig(new Config())))->respond(new RequestContext('GET', '/multi'));
        self::assertNotNull($baseline);

        $throwing = new class implements HealthObserver, Observer {
            public function onSeedHealth(array $report): void
            {
                throw new \RuntimeException('health observer boom');
            }

            public function onDetection(RequestContext $r, Detection $d): void
            {
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
            }
        };
        // Construction must not throw despite the throwing onSeedHealth.
        $honeypot = new Honeypot($this->store(), $this->respondConfig(new Config()), $throwing);
        $served = $honeypot->respond(new RequestContext('GET', '/multi'));
        self::assertNotNull($served);
        self::assertSame($baseline->body, $served->body);
        self::assertSame($this->stableHeaders($baseline->headers), $this->stableHeaders($served->headers));
    }

    public function test_a_plain_observer_is_never_offered_the_report(): void
    {
        // A plain Observer (no HealthObserver) is simply not called for health — and construction works.
        $plain = new class implements Observer {
            public function onDetection(RequestContext $r, Detection $d): void
            {
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
            }
        };
        $honeypot = new Honeypot($this->store(), $this->respondConfig(new Config()), $plain);
        self::assertIsArray($honeypot->seedHealth());
        // No exception, no interface confusion — a plain Observer coexists with the optional push seam.
        self::assertNotNull($honeypot->respond(new RequestContext('GET', '/multi')));
    }

    // --- (e) cross-tier derivation vectors --------------------------------------------------------

    public function test_seed_from_material_vectors_are_the_literal_formula(): void
    {
        foreach (['', 'funnypot', 'x'] as $material) {
            $expected = (int) hexdec(substr(hash('sha256', 'funnypot-persona|' . $material), 0, 15));
            self::assertSame($expected, PersonaIdentity::seedFromMaterial($material), "material '{$material}'");
        }
    }
}
