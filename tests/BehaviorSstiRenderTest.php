<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Rules\PhpLiteralValidator;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The `ssti-render` behavior primitive: the multi-fence SSTI decoy (tplmap-class confirmation).
 * Walks the reflected `surface` capture as a run of engine template fences, evaluates EACH fence's
 * inner arithmetic via Support\SafeArithmetic (a hand-written parser, never eval), and concatenates
 * the computed integers + fixed transforms. Pins with fixture rules (never the shipped compiled file
 * — one integration case at the end uses the corpus to prove the >=2-fence gate does not shadow 45):
 *  - each fence computes; the whole run is stitched; ONLY the render is reflected, never raw bytes;
 *  - the walker FAILS CLOSED on any byte that is neither a recognised fence nor a [ \t] gap;
 *  - any unsafe / out-of-grammar case degrades to the base response — never a 500;
 *  - captures-only, so it renders identically on the facade and the position-blind port.
 */
final class BehaviorSstiRenderTest extends TestCase
{
    /**
     * An ssti-render fixture: the whole query captures into `surface`, the concatenated render is
     * bound to `rendered` and echoed as R={{match.rendered}}. All six engines enabled.
     *
     * @param array<int,string> $engines
     * @return array<string,mixed>
     */
    private function sstiRule(array $engines = ['jinja2', 'twig', 'freemarker', 'erb', 'javascript', 'mako'], int $maxLen = 256): array
    {
        return [
            'id' => 'ssti-fixture',
            'severity' => 'high',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'query', 'regex' => '(?P<surface>.+)', 'capture' => true]],
            'response' => ['headers' => [], 'body' => 'BASE FALLBACK'],
            'behavior' => 'ssti-render',
            'ssti-render' => [
                'response' => ['headers' => [], 'body' => 'R={{match.rendered}}'],
                'surface' => 'surface',
                'bind' => 'rendered',
                'engines' => $engines,
                'max_operand' => 2147483647,
                'max_len' => $maxLen,
            ],
        ];
    }

    private function serve(array $rule, string $query): ?object
    {
        $em = new TemplateAttackEmulator([$rule]);

        return $em->emulate(new RequestContext('GET', '/x', $query));
    }

    // --- handler behavior -------------------------------------------------------------------

    public function test_jinja_multi_fence_stitched_real_tplmap_randoms(): void
    {
        // A REALISTIC tplmap probe: 10-digit header/trailer randoms (in [1e9,1e10), past int32) +
        // an arithmetic payload. The randoms echo via the bare-integer path; the payload computes.
        // Catches the shipped-45 bug of emitting only the first fence, any echo-the-payload path, AND
        // the int32 regression where a 10-digit random would null the whole render.
        $r = $this->serve($this->sstiRule(), '{{9876543210}}{{17*42}}{{1234567890}}');
        self::assertNotNull($r);
        self::assertSame('R=98765432107141234567890', $r->body); // 9876543210 . 714 . 1234567890
    }

    public function test_freemarker_fence_per_engine_with_c_builtin(): void
    {
        // tplmap's FreeMarker header/trailer is `${<10-digit>?c}` (the computer-format builtin).
        // Catches a hard-coded {{-only recogniser that ignores ${...}, and a missing `?c` shape.
        $r = $this->serve($this->sstiRule(), '${9876543210?c}${7*7}${1234567890?c}');
        self::assertNotNull($r);
        self::assertSame('R=9876543210491234567890', $r->body);
    }

    public function test_freemarker_bare_ten_digit_fence(): void
    {
        $r = $this->serve($this->sstiRule(), '${111111111}${7*7}${222222222}');
        self::assertNotNull($r);
        self::assertSame('R=11111111149222222222', $r->body);
    }

    public function test_computes_not_a_canned_constant(): void
    {
        // Product 42, not 49: proves live per-fence computation, not a lookup-table fake.
        $r = $this->serve($this->sstiRule(), '{{10}}{{6*7}}{{20}}');
        self::assertNotNull($r);
        self::assertSame('R=104220', $r->body);
    }

    public function test_twig_nl2br_shape(): void
    {
        // Catches treating |nl2br as a grammar byte (would decline) instead of a recognised strip.
        $r = $this->serve($this->sstiRule(), '{{100}}{{7*7|nl2br}}{{200}}');
        self::assertNotNull($r);
        self::assertSame('R=10049200', $r->body);
    }

    public function test_javascript_typeof_fixed_transform(): void
    {
        // Catches arithmetic-eval'ing typeof(...) (declines) or leaking the raw typeof(7) bytes:
        // the shape emits the CONSTANT word `number` + the validated integer only.
        $r = $this->serve($this->sstiRule(), '${1}${typeof(7)+7}${2}');
        self::assertNotNull($r);
        self::assertSame('R=1number72', $r->body);
    }

    public function test_mako_print_shape(): void
    {
        $r = $this->serve($this->sstiRule(), '${1}${print(6*7)}${2}');
        self::assertNotNull($r);
        self::assertSame('R=1422', $r->body);
    }

    public function test_out_of_grammar_is_inert(): void
    {
        // The core no-attacker-byte-reflection guarantee: a hostile object-access payload must reflect
        // NOTHING and never 500 — the whole render declines to the base page.
        $r = $this->serve($this->sstiRule(), '{{config.items()}}{{7*7}}{{x}}');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_class_gadget_is_inert(): void
    {
        $r = $this->serve($this->sstiRule(), "{{''.__class__.__mro__}}{{7*7}}");
        self::assertSame('BASE FALLBACK', $r->body);
        $r2 = $this->serve($this->sstiRule(), '${T(java.lang.Runtime)}${7*7}');
        self::assertSame('BASE FALLBACK', $r2->body);
    }

    public function test_walker_fails_closed_on_interleaved_bytes(): void
    {
        // A <script> between two valid fences is neither a fence nor a [ \t] gap -> decline the whole
        // render (no raw byte survives). This is the entire fail-closed guarantee.
        $r = $this->serve($this->sstiRule(), '{{7}}<script>{{7}}');
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
        // A non-space inter-fence byte (comma) also declines.
        self::assertSame('BASE FALLBACK', $this->serve($this->sstiRule(), '{{7*7}},{{8}}')->body);
    }

    public function test_digit_echo_admits_no_non_digit_byte(): void
    {
        // The bare-integer echo path is strictly [0-9]-only: a non-digit glued to a random makes the
        // inner neither a bare integer nor arithmetic -> null -> whole render declines. No leak.
        self::assertSame('BASE FALLBACK', $this->serve($this->sstiRule(), '{{9876543210x}}{{7*7}}')->body);
        self::assertSame('BASE FALLBACK', $this->serve($this->sstiRule(), '{{9876543210<b>}}{{7}}')->body);
        // A run longer than the 32-digit echo cap falls through to SafeArithmetic and is rejected
        // there (past int32) -> decline.
        self::assertSame('BASE FALLBACK', $this->serve($this->sstiRule(), '{{999999999999999999999999999999999}}{{7}}')->body);
    }

    public function test_div_zero_and_overflow_degrade_without_500(): void
    {
        $r = $this->serve($this->sstiRule(), '{{1/0}}{{1}}');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('BASE FALLBACK', $r->body);

        $r2 = $this->serve($this->sstiRule(), '{{99999999999999*2}}{{1}}'); // operand past int32
        self::assertSame('BASE FALLBACK', $r2->body);
    }

    public function test_single_fence_declines_below_the_two_fence_gate(): void
    {
        // The fixture rule fires only on >= 2 fences; a lone fence declines to base.
        $r = $this->serve($this->sstiRule(), '{{7*7}}');
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_oversized_surface_degrades_to_base(): void
    {
        $r = $this->serve($this->sstiRule(['jinja2'], 12), '{{123456}}{{7}}'); // 15 chars, cap 12
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_disabled_engine_declines(): void
    {
        // With only jinja2 enabled, a ${...} freemarker run is not a recognised fence -> decline.
        $r = $this->serve($this->sstiRule(['jinja2']), '${1}${7*7}${2}');
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_only_digits_and_fixed_words_are_reflected(): void
    {
        // No raw {, <, ., quote can survive: every rendered body is digits + optional `number` tokens.
        foreach ([
            '{{9876543210}}{{17*42}}{{1234567890}}',
            '${9876543210?c}${7*7}${1234567890?c}',
            '{{10}}{{6*7}}{{20}}',
            '{{100}}{{7*7|nl2br}}{{200}}',
            '${1}${typeof(7)+7}${2}',
        ] as $q) {
            $body = $this->serve($this->sstiRule(), $q)->body;
            self::assertSame(1, preg_match('~^R=(?:[0-9]|number)*$~', $body), $q . ' => ' . $body);
        }
    }

    public function test_facade_equals_port_render(): void
    {
        // Captures-only: renderRule with vs without $r must be byte-identical (position-blind).
        $em = new TemplateAttackEmulator([$this->sstiRule()]);
        $rule = $this->sstiRule();
        $captures = ['surface' => '{{7*7}}{{8}}'];

        $facade = $em->renderRule($rule, $captures, 0, new RequestContext('GET', '/x', '{{7*7}}{{8}}'));
        $port = $em->renderRule($rule, $captures, 0, null);
        self::assertNotNull($facade);
        self::assertNotNull($port);
        self::assertSame('R=498', $facade->body);
        self::assertSame($facade->body, $port->body);
    }

    // --- integration against the compiled corpus -------------------------------------------

    public function test_single_fence_still_routes_to_45_not_shadowed(): void
    {
        // The shipped rule's >=2-fence gate must not steal single-fence probes from 45.
        $em = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
        $r = $em->emulate(new RequestContext('GET', '/hello', 'name={{7*7}}'));
        self::assertNotNull($r);
        self::assertSame(['attack-ssti-numeric'], $r->satisfies->templateIds());
        self::assertSame("49\n", $r->body);
    }

    public function test_multi_fence_routes_to_43_with_real_tplmap_randoms(): void
    {
        $em = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
        $r = $em->emulate(new RequestContext('GET', '/hello', 'x={{9876543210}}{{17*42}}{{1234567890}}'));
        self::assertNotNull($r);
        self::assertSame(['attack-ssti-multifence'], $r->satisfies->templateIds());
        self::assertSame("98765432107141234567890\n", $r->body);
    }

    public function test_freemarker_c_builtin_routes_to_43(): void
    {
        $em = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
        $r = $em->emulate(new RequestContext('GET', '/hello', 'x=${9876543210?c}${7*7}${1234567890?c}'));
        self::assertNotNull($r);
        self::assertSame(['attack-ssti-multifence'], $r->satisfies->templateIds());
        self::assertSame("9876543210491234567890\n", $r->body);
    }

    // --- compiler ---------------------------------------------------------------------------

    public function test_compiler_emits_ssti_render_config(): void
    {
        $rules = $this->compileOne(<<<'YAML'
id: ssti-compile
severity: high
tags: [test]
status: 200
match:
  - in: request
    regex: '(?P<surface>[^&]+)'
    capture: true
response:
  body: BASE
behavior: ssti-render
ssti-render:
  surface: surface
  bind: out
  engines: [jinja2, freemarker]
  max_operand: 999999999999
  max_len: 999
  response:
    headers: { Content-Type: "text/html; charset=utf-8" }
    body: "{{match.out}}"
YAML);
        self::assertCount(1, $rules);
        $rule = $rules[0];
        self::assertSame('ssti-render', $rule['behavior']);
        self::assertSame('surface', $rule['ssti-render']['surface']);
        self::assertSame('out', $rule['ssti-render']['bind']);
        self::assertSame(['jinja2', 'freemarker'], $rule['ssti-render']['engines']);
        // Both caps clamp down to their hard ceilings.
        self::assertSame(2147483647, $rule['ssti-render']['max_operand']);
        self::assertSame(256, $rule['ssti-render']['max_len']);

        $php = "<?php\n\nreturn " . var_export($rules, true) . ";\n";
        self::assertTrue((new PhpLiteralValidator())->isValid($php), 'compiled ssti-render rule must be a pure array literal');
    }

    public function test_compiler_defaults_all_engines_when_omitted(): void
    {
        $rules = $this->compileOne(<<<'YAML'
id: ssti-default-engines
match:
  - in: request
    regex: '(?P<surface>[^&]+)'
    capture: true
response:
  body: BASE
behavior: ssti-render
ssti-render:
  surface: surface
  response:
    body: "{{match.rendered}}"
YAML);
        self::assertSame(['jinja2', 'twig', 'freemarker', 'erb', 'javascript', 'mako'], $rules[0]['ssti-render']['engines']);
        self::assertSame('rendered', $rules[0]['ssti-render']['bind']);
    }

    public function test_compiler_rejects_missing_response(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: ssti-noresp
match:
  - in: request
    contains: x
response:
  body: base
behavior: ssti-render
ssti-render:
  surface: surface
YAML);
    }

    public function test_compiler_rejects_missing_surface(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: ssti-nosurface
match:
  - in: request
    contains: x
response:
  body: base
behavior: ssti-render
ssti-render:
  response:
    body: "{{match.rendered}}"
YAML);
    }

    public function test_compiler_rejects_unknown_engine(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: ssti-badengine
match:
  - in: request
    contains: x
response:
  body: base
behavior: ssti-render
ssti-render:
  surface: surface
  engines: [jinja2, php-eval]
  response:
    body: "{{match.rendered}}"
YAML);
    }

    public function test_compiler_rejects_bad_directive_in_response(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: ssti-baddir
match:
  - in: request
    contains: x
response:
  body: base
behavior: ssti-render
ssti-render:
  surface: surface
  response:
    body: "{{bogus.directive}}"
YAML);
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function compileOne(string $yaml): array
    {
        $dir = sys_get_temp_dir() . '/funnypot-ssti-' . getmypid() . '-' . uniqid();
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
