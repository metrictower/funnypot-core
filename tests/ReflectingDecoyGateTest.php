<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The reflecting-decoy gate: decoys that echo attacker request bytes into an active context (an
 * HTML body or a redirect Location) are safe bait only from an isolated origin. Off one (the
 * fail-safe default — an embedded/inline host), the engine WITHHOLDS the reflection while keeping
 * the detection, so the intel is captured and the host never gains a live XSS/open-redirect.
 *
 * Covers both serve tiers through the single convergence seam (Honeypot::buildAttackFake): the
 * attack tier (attack-xss, attack-open-redirect) and the param tier (param-vite-fs, which rides an
 * attack handle and resolves through ruleById() here too).
 */
final class ReflectingDecoyGateTest extends TestCase
{
    /**
     * $isolatedOrigin is the LAST constructor param; set it as the public property so the
     * preceding args stay positional (PHP 7.3 has no named arguments).
     */
    private function honeypot(bool $isolatedOrigin): Honeypot
    {
        $config = new Config(
            'respond',                                                  // mode
            static function (RequestContext $r): bool { return true; }, // gate
            'matched-only',                                             // pathScope
            null,                                                       // personaSeed
            'coherent',                                                 // personaBreadth
            Style::MINIMAL,                                             // responseStyle
            'high',                                                     // severityCeiling
            65536,                                                      // maxBodyBytes
            0,                                                          // latencyMs
            0,                                                          // latencyJitterMs
            true                                                        // attackEmulation
        );
        $config->isolatedOrigin = $isolatedOrigin;

        return Honeypot::default($config);
    }

    /**
     * As honeypot(), but also sets the per-class serve override map (Config::$reflectClasses).
     * Set as the public property for the same positional-arg reason as $isolatedOrigin.
     *
     * @param array<string,bool> $reflectClasses
     */
    private function honeypotWithClasses(bool $isolatedOrigin, array $reflectClasses): Honeypot
    {
        $config = new Config(
            'respond',                                                  // mode
            static function (RequestContext $r): bool { return true; }, // gate
            'matched-only',                                             // pathScope
            null,                                                       // personaSeed
            'coherent',                                                 // personaBreadth
            Style::MINIMAL,                                             // responseStyle
            'high',                                                     // severityCeiling
            65536,                                                      // maxBodyBytes
            0,                                                          // latencyMs
            0,                                                          // latencyJitterMs
            true                                                        // attackEmulation
        );
        $config->isolatedOrigin = $isolatedOrigin;
        $config->reflectClasses = $reflectClasses;

        return Honeypot::default($config);
    }

    private static function xssRequest(): RequestContext
    {
        return new RequestContext('GET', '/nope', 'q=<script>alert(document.domain)</script>');
    }

    private static function redirectRequest(): RequestContext
    {
        return new RequestContext('GET', '/go', 'url=https://evil.example/phish');
    }

    private static function viteFsRequest(): RequestContext
    {
        // A path OFF the traversal-read allow list, so the base response (which reflects the raw
        // {{match.path}}) renders rather than a canned loot file.
        return new RequestContext('GET', '/@fs/attacker/marker-ABC123', '');
    }

    private static function sqliRequest(): RequestContext
    {
        return new RequestContext('GET', '/item', "id=1' OR '1'='1");
    }

    // --- embedded (isolatedOrigin=false, the fail-safe default): detection kept, reflection withheld ---

    public function test_embedded_suppresses_xss_reflection_but_still_detects(): void
    {
        $hp = $this->honeypot(false);

        $verdict = $hp->classify(self::xssRequest(), SiteProfile::empty());
        self::assertTrue($verdict->classification === \Funnypot\Core\Verdict::ATTACK_CLASS);
        self::assertSame(['attack-xss'], $verdict->detection->templateIds());

        // The reflection is withheld — the host serves its own 404.
        self::assertNull($hp->respond(self::xssRequest()));
    }

    public function test_embedded_suppresses_open_redirect_but_still_detects(): void
    {
        $hp = $this->honeypot(false);

        $verdict = $hp->classify(self::redirectRequest(), SiteProfile::empty());
        self::assertTrue($verdict->classification === \Funnypot\Core\Verdict::ATTACK_CLASS);
        self::assertSame(['attack-open-redirect'], $verdict->detection->templateIds());

        self::assertNull($hp->respond(self::redirectRequest()));
    }

    public function test_embedded_suppresses_param_reflection_but_still_detects(): void
    {
        $hp = $this->honeypot(false);

        // The param tier is guarded through the same serve seam (ruleById resolves param entries).
        $verdict = $hp->classify(self::viteFsRequest(), SiteProfile::empty());
        self::assertTrue($verdict->classification === \Funnypot\Core\Verdict::ATTACK_CLASS);
        self::assertSame(['param-vite-fs'], $verdict->detection->templateIds());

        self::assertNull($hp->respond(self::viteFsRequest()));
    }

    public function test_embedded_still_serves_a_non_reflecting_attack(): void
    {
        // The guard is narrow: a non-reflecting decoy (sqli) is served in embedded mode too.
        $resp = $this->honeypot(false)->respond(self::sqliRequest());
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
    }

    // --- isolated origin (isolatedOrigin=true): reflecting bait serves intact ---

    public function test_isolated_serves_the_xss_reflection(): void
    {
        $resp = $this->honeypot(true)->respond(self::xssRequest());
        self::assertNotNull($resp);
        self::assertStringContainsString('<script>alert(document.domain)</script>', $resp->body);
    }

    public function test_isolated_serves_the_open_redirect(): void
    {
        $resp = $this->honeypot(true)->respond(self::redirectRequest());
        self::assertNotNull($resp);
        self::assertSame(302, $resp->status);
        self::assertSame('https://evil.example/phish', $resp->headers['Location']);
    }

    public function test_isolated_serves_the_param_reflection(): void
    {
        $resp = $this->honeypot(true)->respond(self::viteFsRequest());
        self::assertNotNull($resp);
        self::assertStringContainsString('/@fs/attacker/marker-ABC123', $resp->body);
    }

    public function test_isolated_still_serves_a_non_reflecting_attack(): void
    {
        $resp = $this->honeypot(true)->respond(self::sqliRequest());
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
    }

    // --- the compiled attribute rides through both compilers onto the reflecting rules only ---

    public function test_reflecting_rules_carry_the_compiled_attribute(): void
    {
        $attack = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');

        self::assertTrue(!empty($attack->ruleById('attack-xss')['reflects_input']));
        self::assertTrue(!empty($attack->ruleById('attack-open-redirect')['reflects_input']));

        // A bounded-capture reflector (HTML-safe by construction) is NOT tagged.
        self::assertTrue(empty($attack->ruleById('attack-phpcgi-1823')['reflects_input']));

        // The param tier carries the same attribute (ruleById resolves param entries).
        self::assertTrue(!empty($attack->ruleById('param-vite-fs')['reflects_input']));
    }

    public function test_exactly_the_three_reflectors_are_tagged_in_the_artifacts(): void
    {
        $attackSrc = (string) file_get_contents(__DIR__ . '/../resources/compiled/funnypot-attack.php');
        $paramSrc = (string) file_get_contents(__DIR__ . '/../resources/compiled/funnypot-param.php');

        self::assertSame(2, substr_count($attackSrc, 'reflects_input'));
        self::assertSame(1, substr_count($paramSrc, 'reflects_input'));

        // The explicit reflect_class tag rides alongside reflects_input, one per reflector.
        self::assertSame(2, substr_count($attackSrc, 'reflect_class'));
        self::assertSame(1, substr_count($paramSrc, 'reflect_class'));
    }

    public function test_reflecting_rules_carry_the_reflect_class(): void
    {
        $attack = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');

        self::assertSame('xss', $attack->ruleById('attack-xss')['reflect_class']);
        self::assertSame('open-redirect', $attack->ruleById('attack-open-redirect')['reflect_class']);
        // The param tier carries the class too (ruleById resolves param entries).
        self::assertSame('fs-read', $attack->ruleById('param-vite-fs')['reflect_class']);
    }

    // --- the per-class knob (Config::$reflectClasses): AND-composes with isolatedOrigin, subtract-only ---

    /**
     * THE FAIL-SAFE PROOF (AC 4). An embedded host (isolatedOrigin=false) NEVER reflects, even when
     * every reflect class is explicitly enabled in the map. The isolatedOrigin term dominates the
     * AND — the knob can only ever subtract, never re-enable reflection in a response-owning host.
     */
    public function test_embedded_never_reflects_regardless_of_class_knob(): void
    {
        $hp = $this->honeypotWithClasses(false, [
            'xss' => true,
            'open-redirect' => true,
            'fs-read' => true,
            'default' => true,
        ]);

        self::assertNull($hp->respond(self::xssRequest()));
        self::assertNull($hp->respond(self::redirectRequest()));
        self::assertNull($hp->respond(self::viteFsRequest()));
    }

    public function test_isolated_default_map_still_serves_all_three(): void
    {
        // Empty map + missing-key-⇒-enabled ⇒ byte-behaviour unchanged from today.
        $hp = $this->honeypotWithClasses(true, []);

        $xss = $hp->respond(self::xssRequest());
        self::assertNotNull($xss);
        self::assertStringContainsString('<script>alert(document.domain)</script>', $xss->body);

        $redirect = $hp->respond(self::redirectRequest());
        self::assertNotNull($redirect);
        self::assertSame(302, $redirect->status);

        $vite = $hp->respond(self::viteFsRequest());
        self::assertNotNull($vite);
        self::assertStringContainsString('/@fs/attacker/marker-ABC123', $vite->body);
    }

    public function test_isolated_can_disable_only_the_xss_class(): void
    {
        $hp = $this->honeypotWithClasses(true, ['xss' => false]);

        // XSS withheld ...
        self::assertNull($hp->respond(self::xssRequest()));

        // ... while the other two classes still reflect (independence).
        $redirect = $hp->respond(self::redirectRequest());
        self::assertNotNull($redirect);
        self::assertSame(302, $redirect->status);

        $vite = $hp->respond(self::viteFsRequest());
        self::assertNotNull($vite);
        self::assertStringContainsString('/@fs/attacker/marker-ABC123', $vite->body);
    }

    public function test_isolated_can_disable_only_the_open_redirect_class(): void
    {
        $hp = $this->honeypotWithClasses(true, ['open-redirect' => false]);

        self::assertNull($hp->respond(self::redirectRequest()));

        $xss = $hp->respond(self::xssRequest());
        self::assertNotNull($xss);
        self::assertStringContainsString('<script>alert(document.domain)</script>', $xss->body);

        $vite = $hp->respond(self::viteFsRequest());
        self::assertNotNull($vite);
        self::assertStringContainsString('/@fs/attacker/marker-ABC123', $vite->body);
    }

    public function test_isolated_can_disable_only_the_fs_read_class(): void
    {
        $hp = $this->honeypotWithClasses(true, ['fs-read' => false]);

        self::assertNull($hp->respond(self::viteFsRequest()));

        $xss = $hp->respond(self::xssRequest());
        self::assertNotNull($xss);
        self::assertStringContainsString('<script>alert(document.domain)</script>', $xss->body);

        $redirect = $hp->respond(self::redirectRequest());
        self::assertNotNull($redirect);
        self::assertSame(302, $redirect->status);
    }

    // --- Config::serveReflector() pure logic: the four-row truth table of §2b ---

    public function test_serve_reflector_and_composes_with_isolated_origin(): void
    {
        // [isolatedOrigin, class map, class asked, expected serveReflector]
        $cases = [
            // embedded — withheld even when the class map says true (fail-safe, AC 4)
            [false, ['xss' => true], 'xss', false],
            [false, [], 'xss', false],
            // isolated, class absent ⇒ enabled (unchanged from today)
            [true, [], 'xss', true],
            // isolated, class explicitly true ⇒ enabled
            [true, ['xss' => true], 'xss', true],
            // isolated, class explicitly false ⇒ withheld (per-class opt-out)
            [true, ['xss' => false], 'xss', false],
        ];

        foreach ($cases as $i => [$isolated, $map, $class, $expected]) {
            $config = new Config();
            $config->isolatedOrigin = $isolated;
            $config->reflectClasses = $map;
            self::assertSame(
                $expected,
                $config->serveReflector($class),
                "serveReflector row {$i}"
            );
        }

        // reflectClassEnabled is missing-key-⇒-true, independent of isolatedOrigin.
        $c = new Config();
        self::assertTrue($c->reflectClassEnabled('anything-unset'));
        $c->reflectClasses = ['open-redirect' => false];
        self::assertFalse($c->reflectClassEnabled('open-redirect'));
        self::assertTrue($c->reflectClassEnabled('xss'));
    }

    // --- dalfox selectivity (verify-only, §3): raw markup reflects, plain sentinels do not ---

    public function test_dalfox_plain_sentinel_is_not_reflected(): void
    {
        // dalfox probes reflect-everything hosts with fixed plain-alphanumeric sentinels. Ours does
        // NOT match the markup-shaped XSS regex, so it is never reflected — the host does not present
        // as a reflect-everything origin and dodges dalfox's EWMA collapse. Isolated origin so the
        // gate itself is open; selectivity, not the gate, is what withholds the echo.
        $hp = $this->honeypot(true);

        // Positive control on the SAME path/harness: a markup-shaped payload IS reflected under the
        // open gate, proving the reflect path is live here — so the sentinel's non-reflection below is
        // selectivity, not a dead/non-matching path (guards against this test passing vacuously).
        $live = $hp->respond(self::xssRequest());
        self::assertNotNull($live, 'markup payload must reflect under isolated origin (reflect path live)');
        self::assertStringContainsString('<script>alert(document.domain)</script>', $live->body);

        // The plain sentinel does not match the markup-shaped XSS regex, so it is never echoed.
        $resp = $hp->respond(new RequestContext('GET', '/nope', 'q=dlfx_sentinel_q_8a3f'));
        if ($resp !== null) {
            self::assertStringNotContainsString('dlfx_sentinel_q_8a3f', $resp->body);
        } else {
            self::assertNull($resp);
        }
    }
}
