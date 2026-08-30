<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

/**
 * The param-route tier: a parameterized path (`/@fs/{path}`) the exact O(1) store can't key,
 * dispatched by prefix bucket BETWEEN the exact-store miss and the linear attack scan. It is
 * modeled as an attack-tier-style rule (compiled path regex + named captures + a normal response)
 * and reuses the attack render path verbatim. Precedence: exact route > param route > attack scan.
 */
final class ParamRouteTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    /** A detect-mode engine with the attack + param tiers live (over the packaged param artifact). */
    private function engine(?PhpArrayStore $store = null): Honeypot
    {
        return new Honeypot($store ?? $this->store(), new Config(
            'detect',
            null,
            'matched-only',
            null,
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            0,
            0,
            true // attackEmulation ⇒ builds the emulator, which loads the param buckets
        ));
    }

    /** A respond-mode engine (open gate) so we can assert the served body. */
    private function responder(): Honeypot
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            null,
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            0,
            0,
            true
        );
        // The /@fs route reflects the attacker path into its base body — a reflecting decoy that
        // serves only from an isolated origin, which the served-body assertions below exercise.
        $config->isolatedOrigin = true;

        return new Honeypot($this->store(), $config);
    }

    public function test_matches_and_captures_the_spanning_path(): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', '/@fs/etc/passwd'), SiteProfile::empty());

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);
        self::assertSame('param-vite-fs', $verdict->fakeHandle->ruleId);
        self::assertSame('etc/passwd', $verdict->fakeHandle->captures['path']);
        self::assertSame(['param-vite-fs'], $verdict->detection->templateIds());
    }

    public function test_exact_route_wins_over_a_shape_matching_param(): void
    {
        // A path that is BOTH an exact store key AND shape-matches the param route resolves via the
        // exact tier — the param tier is never consulted.
        $store = new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => ['t-fs' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'FS']],
            'routes' => [
                'GET /@fs/real' => ['b' => [
                    ['s' => 200, 'bw' => ['REAL'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'low', 'sig' => 0, 't' => ['t-fs']],
                ]],
            ],
        ]);

        $verdict = $this->engine($store)->classify(new RequestContext('GET', '/@fs/real'), SiteProfile::empty());

        self::assertSame(FakeHandle::KIND_ROUTE, $verdict->fakeHandle->kind);
        self::assertSame('GET /@fs/real', $verdict->fakeHandle->key);
        self::assertSame(['t-fs'], $verdict->detection->templateIds());
        self::assertNotContains('param-vite-fs', $verdict->detection->templateIds());
    }

    public function test_param_wins_over_the_attack_scan(): void
    {
        // /@fs/../../etc/passwd ALSO matches the generic LFI attack rule (traversal + etc/passwd),
        // but the param tier runs first and returns — so the verdict names the param route.
        $verdict = $this->engine()->classify(new RequestContext('GET', '/@fs/../../etc/passwd'), SiteProfile::empty());

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertSame('param-vite-fs', $verdict->fakeHandle->ruleId);
        self::assertNotSame('attack-lfi-unix', $verdict->fakeHandle->ruleId);
    }

    public function test_no_subpath_falls_through_to_404(): void
    {
        // /@fs with no subpath does not match `^/@fs/.+$`; the bucket is probed but nothing matches.
        $verdict = $this->engine()->classify(new RequestContext('GET', '/@fs'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
    }

    public function test_unrelated_path_is_a_bucket_miss(): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', '/totally/other'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
    }

    public function test_shipped_fs_route_serves_the_passwd_disclosure(): void
    {
        // The shipped /@fs route now upgrades etc/passwd from a pure echo to a bounded arbitrary-
        // file-read disclosure (the traversal-read primitive). The echo tier mechanism itself is
        // pinned separately below by a non-@fs fixture route.
        $resp = $this->responder()->respond(new RequestContext('GET', '/@fs/etc/passwd'));

        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('root:x:0:0', $resp->body);
        self::assertSame('text/plain; charset=utf-8', $resp->headers['Content-Type']);
    }

    public function test_a_plain_param_route_echoes_its_capture_into_a_plain_body(): void
    {
        // Pure-echo tier mechanism ("captures reach a plain body", no behavior). A FIXTURE param
        // route keeps it pinned now that the shipped /@fs route carries a traversal-read behavior;
        // the emulator is constructed with an injected bucket index so no artifact is touched.
        $buckets = [
            'schema' => 1,
            'buckets' => [
                'echo-fixture' => [
                    [
                        'id' => 'param-echo-fixture',
                        'severity' => 'high',
                        'tags' => [],
                        'status' => 200,
                        'method' => 'GET',
                        'regex' => '^/echo-fixture/(?P<path>.+)$',
                        'captures' => ['path'],
                        'response' => [
                            'headers' => ['Content-Type' => 'text/plain; charset=utf-8'],
                            'body' => "// requested path: /echo-fixture/{{match.path}}\n",
                        ],
                    ],
                ],
            ],
        ];
        $emulator = new TemplateAttackEmulator([], [], null, null, $buckets);

        $hit = $emulator->matchParamRoute(new RequestContext('GET', '/echo-fixture/a/b/c'));
        self::assertNotNull($hit);
        self::assertSame('param-echo-fixture', $hit['rule']['id']);
        self::assertSame('a/b/c', $hit['captures']['path']);

        $resp = $emulator->renderRule($hit['rule'], $hit['captures'], 0);
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertSame("// requested path: /echo-fixture/a/b/c\n", $resp->body);
        self::assertSame('text/plain; charset=utf-8', $resp->headers['Content-Type']);
    }

    public function test_a_param_hit_skips_the_attack_gauntlet(): void
    {
        // Wire a spy whose attack scan (matchRule) throws, delegating the param probe to a real
        // emulator. A param-tier hit must return from classify() BEFORE the scan runs, so no throw
        // and matchRule is never called. (TemplateAttackEmulator is final, so the spy composes one;
        // Honeypot's attackEmulator property is untyped, so reflection can inject a duck-typed spy.)
        $real = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');

        $spy = new class($real) {
            /** @var int */
            public $matchRuleCalls = 0;

            /** @var TemplateAttackEmulator */
            private $real;

            public function __construct(TemplateAttackEmulator $real)
            {
                $this->real = $real;
            }

            public function matchParamRoute(RequestContext $r): ?array
            {
                return $this->real->matchParamRoute($r);
            }

            public function matchRule(RequestContext $r): ?array
            {
                $this->matchRuleCalls++;
                throw new \RuntimeException('the attack gauntlet must be skipped on a param hit');
            }
        };

        $engine = $this->engine();
        $prop = new ReflectionProperty(Honeypot::class, 'attackEmulator');
        $prop->setAccessible(true);
        $prop->setValue($engine, $spy);

        // A param path returns before the (throwing) scan.
        $verdict = $engine->classify(new RequestContext('GET', '/@fs/etc/passwd'), SiteProfile::empty());
        self::assertSame('param-vite-fs', $verdict->fakeHandle->ruleId);
        self::assertSame(0, $spy->matchRuleCalls, 'matchRule (the attack gauntlet) must not be called on a param hit');

        // Sanity: the spy IS wired — a NON-param attack path does reach the scan and throws.
        $threw = false;
        try {
            $engine->classify(new RequestContext('GET', '/nope', 'file=../../etc/passwd'), SiteProfile::empty());
        } catch (\RuntimeException $e) {
            $threw = true;
        }
        self::assertTrue($threw, 'a non-param path must reach matchRule (proving the spy is active)');
        self::assertSame(1, $spy->matchRuleCalls);
    }

    public function test_emulator_match_param_route_short_circuits_on_a_bucket_miss(): void
    {
        // Direct unit check of the tier: a first segment with no bucket returns null immediately;
        // a bucket hit whose regex does not match also returns null (no spanning subpath).
        $emulator = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');

        self::assertNull($emulator->matchParamRoute(new RequestContext('GET', '/totally/other')));
        self::assertNull($emulator->matchParamRoute(new RequestContext('GET', '/@fs')));

        $hit = $emulator->matchParamRoute(new RequestContext('GET', '/@fs/etc/passwd'));
        self::assertNotNull($hit);
        self::assertSame('param-vite-fs', $hit['rule']['id']);
        self::assertSame('etc/passwd', $hit['captures']['path']);
    }
}
