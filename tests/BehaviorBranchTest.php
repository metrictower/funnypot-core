<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\NullEphemeralStore;
use Funnypot\Core\Behavior\SystemClock;
use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Rules\PhpLiteralValidator;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;

/**
 * The behavior-primitive dispatch seam and its one reference primitive, `branch`. Uses fixture
 * rules (never the shipped compiled attack file), so it pins the mechanism, not the corpus:
 *  - a no-behavior rule renders exactly as before (the envelope is unchanged);
 *  - `branch` picks the first case whose `when` holds against the LIVE request, else the default;
 *  - the request reaches the handler only on the facade path — the position-blind port leaves it
 *    null and `branch` degrades to its default there;
 *  - the single C8 header-splitting guard and the app-chosen status stay centralized in renderRule.
 */
final class BehaviorBranchTest extends TestCase
{
    /**
     * A no-behavior fixture rule (compiler-shaped): the plain render path.
     *
     * @return array<string,mixed>
     */
    private function plainRule(): array
    {
        return [
            'id' => 'plain-fixture',
            'severity' => 'high',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'query', 'regex' => 'q=([^&]+)', 'capture' => true]],
            'response' => ['headers' => ['X-Demo' => 'plain'], 'body' => 'HELLO {{match.1}}'],
        ];
    }

    /**
     * A branch fixture rule: two request-keyed cases + a default, over a base response that is the
     * ultimate fallback. Top-level match is path-only, so the cases key on surfaces (query, header)
     * the match itself never gated — proving the request reaches the handler.
     *
     * @return array<string,mixed>
     */
    private function branchRule(): array
    {
        return [
            'id' => 'branch-fixture',
            'severity' => 'high',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'path', 'contains' => '/zzz-branch-fixture']],
            'response' => ['headers' => [], 'body' => 'BASE FALLBACK'],
            'behavior' => 'branch',
            'branch' => [
                'cases' => [
                    [
                        'when' => ['in' => 'query', 'contains' => 'alpha'],
                        'response' => ['headers' => [], 'body' => 'CASE A', 'status' => 201],
                    ],
                    [
                        'when' => ['in' => 'header:User-Agent', 'contains' => 'curl'],
                        'response' => ['headers' => [], 'body' => 'CASE B', 'status' => 202],
                    ],
                ],
                'default' => ['response' => ['headers' => [], 'body' => 'DEFAULT CASE', 'status' => 203]],
            ],
        ];
    }

    private function request(string $query = '', array $headers = []): RequestContext
    {
        return new RequestContext('GET', '/zzz-branch-fixture', $query, $headers);
    }

    // --- backward compatibility -------------------------------------------------------------

    public function test_no_behavior_rule_renders_byte_identically(): void
    {
        $emulator = new TemplateAttackEmulator([$this->plainRule()]);

        $resp = $emulator->emulate($this->requestQ('q=world'));
        self::assertNotNull($resp);
        self::assertSame('HELLO world', $resp->body);
        self::assertSame(['X-Demo' => 'plain'], $resp->headers);
        self::assertSame(200, $resp->status);
        self::assertSame(['plain-fixture'], $resp->satisfies->templateIds());
    }

    public function test_no_behavior_rule_ignores_the_request_argument(): void
    {
        // renderRule with vs without $r is identical for a rule that names no behavior — the seam
        // is inert unless a behavior is authored.
        $emulator = new TemplateAttackEmulator([$this->plainRule()]);
        $rule = $this->plainRule();
        $captures = [0 => 'q=world', 1 => 'world'];

        $withR = $emulator->renderRule($rule, $captures, 0, $this->requestQ('q=world'));
        $withoutR = $emulator->renderRule($rule, $captures, 0);

        self::assertNotNull($withR);
        self::assertNotNull($withoutR);
        self::assertSame($withoutR->body, $withR->body);
        self::assertSame($withoutR->headers, $withR->headers);
        self::assertSame($withoutR->status, $withR->status);
    }

    // --- branch case selection --------------------------------------------------------------

    public function test_branch_picks_the_first_matching_case_then_the_default(): void
    {
        $emulator = new TemplateAttackEmulator([$this->branchRule()]);

        $a = $emulator->emulate($this->request('sel=alpha'));
        self::assertNotNull($a);
        self::assertSame('CASE A', $a->body);
        self::assertSame(201, $a->status);

        $b = $emulator->emulate($this->request('sel=beta', ['User-Agent' => 'curl/7.81']));
        self::assertNotNull($b);
        self::assertSame('CASE B', $b->body);
        self::assertSame(202, $b->status);

        $d = $emulator->emulate($this->request('sel=gamma', ['User-Agent' => 'Mozilla/5.0']));
        self::assertNotNull($d);
        self::assertSame('DEFAULT CASE', $d->body);
        self::assertSame(203, $d->status);
    }

    public function test_request_reaches_the_handler_via_a_header_surface(): void
    {
        // The top-level match gated only the path; case B keys on User-Agent. Selecting it proves
        // the live request (headers and all) is threaded into the branch handler.
        $emulator = new TemplateAttackEmulator([$this->branchRule()]);

        $b = $emulator->emulate($this->request('sel=nomatch', ['User-Agent' => 'curl/8.0']));
        self::assertNotNull($b);
        self::assertSame('CASE B', $b->body);
    }

    // --- the centralized C8 header-splitting guard ------------------------------------------

    public function test_branch_case_header_with_decoded_crlf_is_declined(): void
    {
        // A branch case reflects a captured value into a header; a decoded CR/LF must decline the
        // whole rule (renderRule's single C8 guard), never split a header. Mirrors the open-redirect
        // CRLF case, but through a behavior branch.
        $rule = [
            'id' => 'branch-crlf',
            'severity' => 'high',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'query', 'regex' => 'url=([^&]+)', 'capture' => true]],
            'response' => ['headers' => [], 'body' => 'base'],
            'behavior' => 'branch',
            'branch' => [
                'cases' => [
                    [
                        'when' => ['in' => 'query', 'contains' => 'url='],
                        'response' => [
                            'headers' => ['Location' => '{{urldecode:match.1}}'],
                            'body' => '',
                            'status' => 302,
                        ],
                    ],
                ],
            ],
        ];
        $emulator = new TemplateAttackEmulator([$rule]);

        // A clean redirect renders through the case.
        $ok = $emulator->emulate($this->requestQ('url=https://evil.example/phish'));
        self::assertNotNull($ok);
        self::assertSame(302, $ok->status);
        self::assertSame('https://evil.example/phish', $ok->headers['Location']);

        // A CRLF-bearing one is declined by the header guard.
        self::assertNull($emulator->emulate($this->requestQ('url=https://evil.example/%0d%0aSet-Cookie:x=1')));
    }

    // --- null store / clock defaults are safe ----------------------------------------------

    public function test_default_null_store_and_system_clock_are_safe(): void
    {
        // Constructed without a Clock/EphemeralStore, the emulator wires the safe defaults and a
        // branch rule renders fine — no primitive this milestone consumes them, but the seam holds.
        $emulator = new TemplateAttackEmulator([$this->branchRule()]);
        self::assertNotNull($emulator->emulate($this->request('sel=alpha')));

        $store = $this->privateProp($emulator, 'store');
        $clock = $this->privateProp($emulator, 'clock');
        self::assertInstanceOf(NullEphemeralStore::class, $store);
        self::assertInstanceOf(SystemClock::class, $clock);

        // NullEphemeralStore never remembers: get() is always a miss and put() is a no-op.
        self::assertNull($store->get('anything'));
        $store->put('k', 'v', 10);
        self::assertNull($store->get('k'));

        // SystemClock reports the real wall clock.
        self::assertGreaterThan(0, $clock->now());
    }

    // --- port-path degradation (the critical constraint) ------------------------------------

    public function test_port_path_synthesize_renders_the_default_case(): void
    {
        // The same request that selects CASE A on the facade (emulate, $r present) renders the
        // DEFAULT case through the position-blind port (synthesize, no $r) — proving $r is threaded
        // only on the facade path and a request-aware behavior degrades safely on the port.
        $emulator = new TemplateAttackEmulator([$this->branchRule()]);
        $facade = $emulator->emulate($this->request('sel=alpha'));
        self::assertNotNull($facade);
        self::assertSame('CASE A', $facade->body);

        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
        $engine = new Honeypot($store, new Config(
            'detect',           // mode
            null,               // gate
            'matched-only',     // pathScope
            null,               // personaSeed
            'coherent',         // personaBreadth
            Style::MINIMAL,     // responseStyle
            'high',             // severityCeiling
            65536,              // maxBodyBytes
            0,                  // latencyMs
            0,                  // latencyJitterMs
            true                // attackEmulation
        ));
        // Inject the fixture emulator so the port renders a branch rule without touching the corpus.
        $prop = new ReflectionProperty(Honeypot::class, 'attackEmulator');
        $prop->setAccessible(true);
        $prop->setValue($engine, $emulator);

        $verdict = $engine->classify($this->request('sel=alpha'), SiteProfile::empty());
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);

        $fake = $engine->synthesize($verdict, SiteProfile::empty(), 'seed');
        self::assertNotNull($fake);
        self::assertSame('DEFAULT CASE', $fake->body);
        self::assertSame(203, $fake->status);
    }

    // --- compiler ---------------------------------------------------------------------------

    public function test_compiler_emits_the_branch_config(): void
    {
        $rules = $this->compileOne(<<<'YAML'
id: branch-compile
severity: high
tags: [test]
status: 200
match:
  - in: path
    contains: /zzz-branch-fixture
response:
  body: BASE FALLBACK
behavior: branch
branch:
  cases:
    - when:
        in: query
        contains: alpha
      response:
        status: 201
        body: CASE A
    - when:
        in: header:User-Agent
        contains: curl
      response:
        status: 202
        body: CASE B
  default:
    response:
      status: 203
      body: DEFAULT CASE
YAML);

        self::assertCount(1, $rules);
        $rule = $rules[0];
        self::assertSame('branch', $rule['behavior']);
        self::assertSame(
            [
                'cases' => [
                    [
                        'when' => ['in' => 'query', 'contains' => 'alpha'],
                        'response' => ['headers' => [], 'body' => 'CASE A', 'status' => 201],
                    ],
                    [
                        'when' => ['in' => 'header:User-Agent', 'contains' => 'curl'],
                        'response' => ['headers' => [], 'body' => 'CASE B', 'status' => 202],
                    ],
                ],
                'default' => ['response' => ['headers' => [], 'body' => 'DEFAULT CASE', 'status' => 203]],
            ],
            $rule['branch']
        );

        // The emitted rule (nested branch arrays included) must be pure inert DATA — the same gate
        // the signed rules-update artifacts pass before they are ever require()d.
        $php = "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($rules, true) . ";\n";
        self::assertTrue((new PhpLiteralValidator())->isValid($php), 'compiled branch rule must be a pure array literal');
    }

    public function test_compiler_rejects_an_unknown_behavior(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: bad-behavior
match:
  - in: path
    contains: /x
response:
  body: base
behavior: teleport
YAML);
    }

    public function test_compiler_rejects_empty_branch_cases(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: empty-cases
match:
  - in: path
    contains: /x
response:
  body: base
behavior: branch
branch:
  cases: []
YAML);
    }

    public function test_compiler_rejects_a_bad_directive_in_a_case_response(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: bad-directive
match:
  - in: path
    contains: /x
response:
  body: base
behavior: branch
branch:
  cases:
    - when:
        in: query
        contains: alpha
      response:
        body: "{{bogus.directive}}"
YAML);
    }

    // --- helpers ----------------------------------------------------------------------------

    private function requestQ(string $query): RequestContext
    {
        return new RequestContext('GET', '/anything', $query);
    }

    /** @return mixed */
    private function privateProp(object $obj, string $name)
    {
        $prop = new ReflectionProperty(get_class($obj), $name);
        $prop->setAccessible(true);

        return $prop->getValue($obj);
    }

    /**
     * Compile one YAML template through EmulatorCompiler in an isolated temp dir.
     *
     * @return array<int,array<string,mixed>>
     */
    private function compileOne(string $yaml): array
    {
        $dir = sys_get_temp_dir() . '/funnypot-branch-' . getmypid() . '-' . uniqid();
        if (!mkdir($dir, 0775, true) && !is_dir($dir)) {
            self::fail("cannot create temp corpus dir {$dir}");
        }
        file_put_contents($dir . '/rule.yaml', $yaml);
        try {
            return (new EmulatorCompiler())->compile($dir);
        } finally {
            @unlink($dir . '/rule.yaml');
            @rmdir($dir);
        }
    }
}
