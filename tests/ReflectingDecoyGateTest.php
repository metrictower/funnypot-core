<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Closure;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The reflecting-decoy gate: decoys that echo attacker request bytes into an active context (an
 * HTML body or a redirect Location) are safe bait only from an isolated origin. The serve decision
 * is three subtract-only terms, in order — Config::$isolatedOrigin (operator INTENT), the per-class
 * map, and the request-bound Config::$reflectorAuthorizer (adapter EVIDENCE about this request) — so
 * an embedded host never reflects, and neither does an isolated origin that supplies no evidence.
 * Every suppressed case keeps the detection: the intel is captured, only the reflection is withheld.
 *
 * Covers both serve tiers through the single convergence seam (Honeypot::buildAttackFake): the
 * attack tier (attack-xss, attack-open-redirect) and the param tier (param-vite-fs, which rides an
 * attack handle and resolves through ruleById() here too).
 */
final class ReflectingDecoyGateTest extends TestCase
{
    private const ATTACK_ARTIFACT = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const PARAM_ARTIFACT = __DIR__ . '/../resources/compiled/funnypot-param.php';

    /** Test-only evidence: an authorizer that vouches for every request, so gate-ON rows can run. */
    private static function vouch(): Closure
    {
        return static function (RequestContext $r, string $class): bool { return true; };
    }

    /**
     * $isolatedOrigin / $reflectClasses / $reflectorAuthorizer are trailing constructor params; set
     * them as public properties so the preceding args stay positional (PHP 7.3 has no named arguments).
     *
     * @param array<string,bool> $reflectClasses
     */
    private function honeypot(bool $isolatedOrigin, ?Closure $authorizer = null, array $reflectClasses = []): Honeypot
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
        $config->reflectorAuthorizer = $authorizer;

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

    /** @return array<string,array{0:RequestContext,1:string}> reflect class => [request, rule id] */
    private static function reflectors(): array
    {
        return [
            'xss' => [self::xssRequest(), 'attack-xss'],
            'open-redirect' => [self::redirectRequest(), 'attack-open-redirect'],
            'fs-read' => [self::viteFsRequest(), 'param-vite-fs'],
        ];
    }

    /** Detection recorded (the probe classifies to exactly this rule) but the facade serves nothing. */
    private function assertDetectedButWithheld(Honeypot $hp, RequestContext $r, string $ruleId, string $why): void
    {
        $verdict = $hp->classify($r, SiteProfile::empty());
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, $why);
        self::assertSame([$ruleId], $verdict->detection->templateIds(), $why);
        self::assertNull($hp->respond($r), $why . ': the reflection must be withheld');
    }

    // --- embedded (isolatedOrigin=false, the fail-safe default): detection kept, reflection withheld ---

    public function test_embedded_suppresses_xss_reflection_but_still_detects(): void
    {
        // Even WITH an authorizer vouching: the isolatedOrigin term is first and dominates.
        $this->assertDetectedButWithheld($this->honeypot(false, self::vouch()), self::xssRequest(), 'attack-xss', 'embedded xss');
    }

    public function test_embedded_suppresses_open_redirect_but_still_detects(): void
    {
        $this->assertDetectedButWithheld($this->honeypot(false, self::vouch()), self::redirectRequest(), 'attack-open-redirect', 'embedded redirect');
    }

    public function test_embedded_suppresses_param_reflection_but_still_detects(): void
    {
        // The param tier is guarded through the same serve seam (ruleById resolves param entries).
        $this->assertDetectedButWithheld($this->honeypot(false, self::vouch()), self::viteFsRequest(), 'param-vite-fs', 'embedded vite');
    }

    public function test_embedded_still_serves_a_non_reflecting_attack(): void
    {
        // The guard is narrow: a non-reflecting decoy (sqli) is served in embedded mode too.
        $resp = $this->honeypot(false)->respond(self::sqliRequest());
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
    }

    // --- isolated origin + request-bound evidence: reflecting bait serves intact ---

    public function test_isolated_and_authorized_serves_the_xss_reflection(): void
    {
        $resp = $this->honeypot(true, self::vouch())->respond(self::xssRequest());
        self::assertNotNull($resp);
        self::assertStringContainsString('<script>alert(document.domain)</script>', $resp->body);
    }

    public function test_isolated_and_authorized_serves_the_open_redirect(): void
    {
        $resp = $this->honeypot(true, self::vouch())->respond(self::redirectRequest());
        self::assertNotNull($resp);
        self::assertSame(302, $resp->status);
        self::assertSame('https://evil.example/phish', $resp->headers['Location']);
    }

    public function test_isolated_and_authorized_serves_the_param_reflection(): void
    {
        $resp = $this->honeypot(true, self::vouch())->respond(self::viteFsRequest());
        self::assertNotNull($resp);
        self::assertStringContainsString('/@fs/attacker/marker-ABC123', $resp->body);
    }

    public function test_isolated_still_serves_a_non_reflecting_attack(): void
    {
        $resp = $this->honeypot(true)->respond(self::sqliRequest());
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
    }

    // --- THE SAFETY REGRESSION: intent alone (isolatedOrigin=true, no authorizer) serves nothing ---

    public function test_isolated_origin_alone_no_longer_serves_any_reflector(): void
    {
        // Under the previous contract this configuration served all three. isolatedOrigin is an
        // operator assertion about topology, not evidence about the request's origin; an install
        // that wires no authorizer is therefore safe-off, with its detections intact.
        $hp = $this->honeypot(true);
        foreach (self::reflectors() as $class => [$r, $ruleId]) {
            $this->assertDetectedButWithheld($hp, $r, $ruleId, "intent-only {$class}");
        }
        // Non-reflecting bait is unaffected by the missing authorizer.
        self::assertNotNull($hp->respond(self::sqliRequest()));
    }

    /**
     * @dataProvider nonAuthorizingCallbackProvider
     */
    public function test_a_callback_that_is_not_literally_true_suppresses(string $label, Closure $callback): void
    {
        $hp = $this->honeypot(true, $callback);
        foreach (self::reflectors() as $class => [$r, $ruleId]) {
            $this->assertDetectedButWithheld($hp, $r, $ruleId, "{$label}: {$class}");
        }
        self::assertNotNull($hp->respond(self::sqliRequest()), "{$label}: non-reflecting bait still serves");
    }

    /**
     * @return iterable<string,array{0:string,1:Closure}>
     */
    public static function nonAuthorizingCallbackProvider(): iterable
    {
        yield 'false' => ['false', static function (RequestContext $r, string $c): bool { return false; }];
        yield 'truthy int' => ['truthy int', static function (RequestContext $r, string $c) { return 1; }];
        yield 'truthy string' => ['truthy string', static function (RequestContext $r, string $c) { return 'true'; }];
        yield 'null' => ['null', static function (RequestContext $r, string $c) { return null; }];
        yield 'throws' => ['throws', static function (RequestContext $r, string $c): bool { throw new \RuntimeException('adapter fault'); }];
    }

    public function test_authorizer_runs_once_after_the_cheap_terms_and_sees_the_live_request(): void
    {
        $calls = [];
        $spy = static function (RequestContext $r, string $class) use (&$calls): bool {
            $calls[] = [$r->path, $class];

            return true;
        };

        // Embedded: never consulted (isolatedOrigin rejects first).
        $this->honeypot(false, $spy)->respond(self::xssRequest());
        self::assertSame([], $calls, 'embedded must not consult the authorizer');

        // Isolated but the class is off: never consulted (the class map rejects second).
        $this->honeypot(true, $spy, ['xss' => false])->respond(self::xssRequest());
        self::assertSame([], $calls, 'a disabled class must not consult the authorizer');

        // Isolated + class on: exactly once per decision, with THIS request and ITS reflect class.
        $hp = $this->honeypot(true, $spy);
        self::assertNotNull($hp->respond(self::xssRequest()));
        self::assertSame([['/nope', 'xss']], $calls);
        self::assertNotNull($hp->respond(self::redirectRequest()));
        self::assertSame([['/nope', 'xss'], ['/go', 'open-redirect']], $calls);
        self::assertNotNull($hp->respond(self::viteFsRequest()));
        self::assertSame([['/nope', 'xss'], ['/go', 'open-redirect'], ['/@fs/attacker/marker-ABC123', 'fs-read']], $calls);

        // A non-reflecting decoy never consults it.
        self::assertNotNull($hp->respond(self::sqliRequest()));
        self::assertCount(3, $calls);
    }

    public function test_position_blind_synthesize_has_no_request_and_suppresses_every_reflector(): void
    {
        // The port path (synthesize / synthesizeFromHandle) carries no request, hence no evidence: a
        // reflector is withheld there even with isolatedOrigin=true and an authorizer that vouches.
        $hp = $this->honeypot(true, self::vouch());
        foreach (self::reflectors() as $class => [$r, $ruleId]) {
            $verdict = $hp->classify($r, SiteProfile::empty());
            self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, $class);
            self::assertSame($ruleId, $verdict->fakeHandle->ruleId, $class);
            self::assertNull($hp->synthesize($verdict, SiteProfile::empty(), 'seed'), "{$class}: synthesize must withhold");
            self::assertNull($hp->synthesizeFromHandle($verdict->fakeHandle, SiteProfile::empty(), 'seed'), "{$class}: synthesizeFromHandle must withhold");
            // The same probe DOES serve through the facade, which threads the live request.
            self::assertNotNull($hp->respond($r), "{$class}: respond serves");
        }
        // Non-reflecting bait synthesizes on the port path as before.
        $sqli = $hp->classify(self::sqliRequest(), SiteProfile::empty());
        self::assertNotNull($hp->synthesize($sqli, SiteProfile::empty(), 'seed'));
    }

    // --- the compiled attribute rides through both compilers onto the reflecting rules only ---

    public function test_reflecting_rules_carry_the_compiled_attribute(): void
    {
        $attack = TemplateAttackEmulator::fromFile(self::ATTACK_ARTIFACT);

        self::assertTrue(!empty($attack->ruleById('attack-xss')['reflects_input']));
        self::assertTrue(!empty($attack->ruleById('attack-xss-escalation')['reflects_input']));
        self::assertTrue(!empty($attack->ruleById('attack-open-redirect')['reflects_input']));

        // A bounded-capture reflector (HTML-safe by construction) is NOT tagged.
        self::assertTrue(empty($attack->ruleById('attack-phpcgi-1823')['reflects_input']));
        self::assertTrue(empty($attack->ruleById('attack-xss-baseline')['reflects_input']));

        // The param tier carries the same attribute (ruleById resolves param entries).
        self::assertTrue(!empty($attack->ruleById('param-vite-fs')['reflects_input']));
    }

    public function test_exactly_the_four_reflectors_are_tagged_in_the_artifacts(): void
    {
        $attackSrc = (string) file_get_contents(self::ATTACK_ARTIFACT);
        $paramSrc = (string) file_get_contents(self::PARAM_ARTIFACT);

        // attack-xss, attack-xss-escalation, attack-open-redirect; param-vite-fs.
        self::assertSame(3, substr_count($attackSrc, 'reflects_input'));
        self::assertSame(1, substr_count($paramSrc, 'reflects_input'));

        // The explicit reflect_class tag rides alongside reflects_input, one per reflector.
        self::assertSame(3, substr_count($attackSrc, 'reflect_class'));
        self::assertSame(1, substr_count($paramSrc, 'reflect_class'));
    }

    public function test_reflecting_rules_carry_the_reflect_class(): void
    {
        $attack = TemplateAttackEmulator::fromFile(self::ATTACK_ARTIFACT);

        self::assertSame('xss', $attack->ruleById('attack-xss')['reflect_class']);
        self::assertSame('xss', $attack->ruleById('attack-xss-escalation')['reflect_class']);
        self::assertSame('open-redirect', $attack->ruleById('attack-open-redirect')['reflect_class']);
        // The param tier carries the class too (ruleById resolves param entries).
        self::assertSame('fs-read', $attack->ruleById('param-vite-fs')['reflect_class']);
    }

    // --- the per-class knob (Config::$reflectClasses): AND-composes, subtract-only ---

    /**
     * THE FAIL-SAFE PROOF. An embedded host (isolatedOrigin=false) NEVER reflects, even when every
     * reflect class is explicitly enabled in the map AND an authorizer vouches. The isolatedOrigin
     * term dominates the AND — no later term can re-enable reflection in a response-owning host.
     */
    public function test_embedded_never_reflects_regardless_of_class_knob(): void
    {
        $hp = $this->honeypot(false, self::vouch(), [
            'xss' => true,
            'open-redirect' => true,
            'fs-read' => true,
            'default' => true,
        ]);

        self::assertNull($hp->respond(self::xssRequest()));
        self::assertNull($hp->respond(self::redirectRequest()));
        self::assertNull($hp->respond(self::viteFsRequest()));
    }

    public function test_isolated_default_map_still_serves_all_three_when_authorized(): void
    {
        // Empty map + missing-key-⇒-enabled: the map adds no restriction of its own.
        $hp = $this->honeypot(true, self::vouch(), []);

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
        $hp = $this->honeypot(true, self::vouch(), ['xss' => false]);

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
        $hp = $this->honeypot(true, self::vouch(), ['open-redirect' => false]);

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
        $hp = $this->honeypot(true, self::vouch(), ['fs-read' => false]);

        self::assertNull($hp->respond(self::viteFsRequest()));

        $xss = $hp->respond(self::xssRequest());
        self::assertNotNull($xss);
        self::assertStringContainsString('<script>alert(document.domain)</script>', $xss->body);

        $redirect = $hp->respond(self::redirectRequest());
        self::assertNotNull($redirect);
        self::assertSame(302, $redirect->status);
    }

    public function test_authorizer_can_re_enable_per_class_only_within_the_map(): void
    {
        // The authorizer receives the reflect class, so an adapter may vouch per class — but it can
        // never override a class the map disabled (the map is checked first and only subtracts).
        $xssOnly = static function (RequestContext $r, string $class): bool { return $class === 'xss'; };
        $hp = $this->honeypot(true, $xssOnly);
        self::assertNotNull($hp->respond(self::xssRequest()));
        self::assertNull($hp->respond(self::redirectRequest()));
        self::assertNull($hp->respond(self::viteFsRequest()));

        $hp = $this->honeypot(true, $xssOnly, ['xss' => false]);
        self::assertNull($hp->respond(self::xssRequest()));
    }

    // --- Config::serveReflector() pure logic: the full truth table ---

    public function test_serve_reflector_truth_table(): void
    {
        $request = new RequestContext('GET', '/x');
        $yes = self::vouch();
        $no = static function (RequestContext $r, string $c): bool { return false; };

        // [isolatedOrigin, class map, request, authorizer, expected]
        $cases = [
            // embedded — withheld whatever else is present (fail-safe)
            [false, ['xss' => true], $request, $yes, false],
            [false, [], $request, $yes, false],
            [false, [], null, null, false],
            // isolated, class enabled (absent or true), but no evidence — withheld
            [true, [], null, null, false],
            [true, [], $request, null, false],
            [true, [], null, $yes, false],
            [true, ['xss' => true], $request, $no, false],
            // isolated, class explicitly off — withheld even with evidence
            [true, ['xss' => false], $request, $yes, false],
            // isolated, class on (absent / true), live request, authorizer literally true — served
            [true, [], $request, $yes, true],
            [true, ['xss' => true], $request, $yes, true],
        ];

        foreach ($cases as $i => [$isolated, $map, $r, $auth, $expected]) {
            $config = new Config();
            $config->isolatedOrigin = $isolated;
            $config->reflectClasses = $map;
            $config->reflectorAuthorizer = $auth;
            self::assertSame($expected, $config->serveReflector('xss', $r), "serveReflector row {$i}");
        }

        // reflectClassEnabled is missing-key-⇒-true, independent of isolatedOrigin.
        $c = new Config();
        self::assertTrue($c->reflectClassEnabled('anything-unset'));
        $c->reflectClasses = ['open-redirect' => false];
        self::assertFalse($c->reflectClassEnabled('open-redirect'));
        self::assertTrue($c->reflectClassEnabled('xss'));

        // reflectorAuthorized is the fail-closed helper on its own: null ⇒ false, === true only, throw ⇒ false.
        $c = new Config();
        self::assertFalse($c->reflectorAuthorized($request, 'xss'));
        $c->reflectorAuthorizer = $yes;
        self::assertTrue($c->reflectorAuthorized($request, 'xss'));
        $c->reflectorAuthorizer = static function (RequestContext $r, string $class) { return 1; };
        self::assertFalse($c->reflectorAuthorized($request, 'xss'));
        $c->reflectorAuthorizer = static function (RequestContext $r, string $class): bool { throw new \LogicException('boom'); };
        self::assertFalse($c->reflectorAuthorized($request, 'xss'));
    }

    public function test_authorizer_is_the_trailing_constructor_parameter(): void
    {
        // Appended last so every existing positional caller keeps its positions (PHP 7.3: no named args).
        $config = new Config(
            'respond', null, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0,
            true, null, null, null, '', [], true, null, null, null, null, null, [],
            true,   // isolatedOrigin
            false, null, false,
            [],     // reflectClasses
            self::vouch()
        );
        self::assertTrue($config->serveReflector('xss', new RequestContext('GET', '/x')));
        self::assertNull((new Config())->reflectorAuthorizer, 'default is null ⇒ every reflector safe-off');
    }

    // --- dalfox selectivity (verify-only): raw markup reflects, plain sentinels do not ---

    public function test_dalfox_plain_sentinel_is_not_reflected(): void
    {
        // dalfox probes reflect-everything hosts with fixed plain-alphanumeric sentinels. Ours does
        // NOT match the markup-shaped XSS regex, so it is never reflected — the host does not present
        // as a reflect-everything origin and dodges dalfox's EWMA collapse. Gate fully open so
        // selectivity, not the gate, is what withholds the echo.
        $hp = $this->honeypot(true, self::vouch());

        // Positive control on the SAME path/harness: a markup-shaped payload IS reflected under the
        // open gate, proving the reflect path is live here — so the sentinel's non-reflection below is
        // selectivity, not a dead/non-matching path (guards against this test passing vacuously).
        $live = $hp->respond(self::xssRequest());
        self::assertNotNull($live, 'markup payload must reflect under the open gate (reflect path live)');
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
