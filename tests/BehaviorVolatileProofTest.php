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
 * FP-0232 — the {{volatile.NAME:ENC:N}} confirmation-resistant proof-token directive. The ARMED path
 * mints a fresh CSPRNG token per render (so a Tier-H retester never reproduces the proof), while persona
 * identity and page structure stay byte-stable. OFF (the default arm) delegates to the stable seeded
 * {{fake.NAME}} path, so a default build is byte-identical to today.
 *
 * These are fixture-driven (never the shipped compiled file). The volatileProof arm is the LAST
 * constructor arg of TemplateAttackEmulator (S1) — the 8th positional here.
 */
final class BehaviorVolatileProofTest extends TestCase
{
    /**
     * A verbose-error fixture: a stable persona identity in the <title> and a volatile error-reference
     * id as the proof token. Single-line so any stray CR/LF/NUL could only come from the token.
     *
     * @return array<string,mixed>
     */
    private function rule(string $token = '{{volatile.errref:hex:16}}'): array
    {
        return [
            'id' => 'volatile-fixture',
            'severity' => 'medium',
            'tags' => [],
            'status' => 500,
            'match' => [['in' => 'query', 'regex' => 'probe=1']],
            'response' => [
                'headers' => ['Content-Type' => 'text/html; charset=utf-8'],
                'body' => '<html><title>{{persona.company.name}}</title><p>Error reference: ' . $token . '</p></html>',
            ],
        ];
    }

    /** Build an emulator with the arm on or off (arm is the 8th/last positional ctor arg — S1). */
    private function emulator(array $rule, bool $volatileProof): TemplateAttackEmulator
    {
        return new TemplateAttackEmulator([$rule], [], null, null, [], null, null, $volatileProof);
    }

    /** The 16-hex proof token span from a rendered body (hex:16 → 64 bits, S2). */
    private function token(string $body): string
    {
        self::assertSame(1, preg_match('/Error reference: ([0-9a-f]{16})</', $body, $m), "no proof token in: {$body}");

        return $m[1];
    }

    /** The stable persona identity from the <title>. */
    private function identity(string $body): string
    {
        self::assertSame(1, preg_match('#<title>(.*?)</title>#', $body, $m), "no persona identity in: {$body}");

        return $m[1];
    }

    // --- THE KEY falsifiable test ------------------------------------------------------------------

    /**
     * ARMED: the same probe served twice must (1) carry an IDENTICAL persona identity (coherence intact),
     * (2) carry a DIFFERENT proof token (non-reproducible — the whole point), and (3) be byte-identical
     * everywhere EXCEPT the token span (structure preserved). One test, three failure modes: feature-dead
     * (token reproduces), coherence-broken (identity churns), structure-corrupted (strip-span inequality).
     */
    public function test_armed_proof_token_does_not_reproduce_but_identity_does(): void
    {
        $em = $this->emulator($this->rule(), true);
        $r = new RequestContext('GET', '/x', 'probe=1');

        $a = $em->emulate($r, 7);
        $b = $em->emulate($r, 7);
        self::assertNotNull($a);
        self::assertNotNull($b);

        // (1) persona identity IDENTICAL across the two requests.
        self::assertSame($this->identity($a->body), $this->identity($b->body), 'persona identity must not churn');
        self::assertNotSame('', $this->identity($a->body), 'persona identity must actually render');

        // (2) the proof token DIFFERS between the two requests (hex:16 = 64 bits, flake ~2^-64).
        self::assertNotSame($this->token($a->body), $this->token($b->body), 'armed proof token must not reproduce');

        // (3) everything EXCEPT the token span is byte-identical — strip the span and compare.
        $mask = static function (string $body): string {
            return (string) preg_replace('/Error reference: [0-9a-f]{16}</', 'Error reference: <TOKEN><', $body);
        };
        self::assertSame($mask($a->body), $mask($b->body), 'non-token bytes must be byte-identical');
    }

    // --- off-by-default: stable AND byte-identical to the fake delegate ----------------------------

    /**
     * OFF (default arm): two identical probes are byte-identical; and the volatile-off token equals the
     * {{fake.errref:hex:16}} token at the same seed — proving the off path is LITERALLY the fake delegate
     * (one source of truth), not a separate implementation that could drift.
     */
    public function test_off_by_default_is_stable_and_byte_identical_to_fake(): void
    {
        $r = new RequestContext('GET', '/x', 'probe=1');

        // Off (default false).
        $off = $this->emulator($this->rule(), false);
        $a = $off->emulate($r, 7);
        $b = $off->emulate($r, 7);
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, 'off-by-default must be byte-identical across requests');

        // A sibling rule that uses {{fake.errref:hex:16}} instead renders the SAME token at the same seed.
        $fake = $this->emulator($this->rule('{{fake.errref:hex:16}}'), false);
        $f = $fake->emulate($r, 7);
        self::assertNotNull($f);
        self::assertSame($f->body, $a->body, 'volatile OFF must be byte-identical to the fake delegate');
    }

    /**
     * The arm truly defaults OFF at the ctor level: a default-constructed emulator (no arm arg) is
     * byte-identical to an explicitly-off one.
     */
    public function test_default_ctor_arm_is_off(): void
    {
        $r = new RequestContext('GET', '/x', 'probe=1');
        $default = new TemplateAttackEmulator([$this->rule()]); // no arm arg
        $explicitOff = $this->emulator($this->rule(), false);

        self::assertSame($explicitOff->emulate($r, 7)->body, $default->emulate($r, 7)->body);
    }

    // --- CRLF + size safety ------------------------------------------------------------------------

    /** The armed token carries no CR/LF/NUL and honors N across the supported encodings. */
    public function test_token_is_crlf_and_size_safe(): void
    {
        $r = new RequestContext('GET', '/x', 'probe=1');

        foreach ([
            '{{volatile.errref:hex:16}}' => '/^[0-9a-f]{16}$/',
            '{{volatile.errref:hexupper:16}}' => '/^[0-9A-F]{16}$/',
            '{{volatile.errref:b64:22}}' => '#^[A-Za-z0-9+/]{22}$#',
            '{{volatile.errref:b64url:22}}' => '/^[A-Za-z0-9_-]{22}$/',
            '{{volatile.errref:dec:16}}' => '/^[1-9][0-9]{15}$/',
        ] as $directive => $shape) {
            $em = $this->emulator($this->rule($directive), true);
            $body = $em->emulate($r, 7)->body;
            self::assertSame(0, preg_match('/[\r\n\x00]/', $body), "control byte in armed body for {$directive}");
            self::assertSame(1, preg_match('#Error reference: ([^<]*)<#', $body, $m));
            self::assertSame(1, preg_match($shape, $m[1]), "token '{$m[1]}' violates shape/length for {$directive}");
        }
    }

    /** The raw token span (between "Error reference: " and the following '<') from a rendered body. */
    private function tokenSpan(string $body): string
    {
        self::assertSame(1, preg_match('#Error reference: ([^<]*)<#', $body, $m), "no token span in: {$body}");

        return $m[1];
    }

    /**
     * ARMED `dec` (opus N1): the token must be all-digits (leading digit non-zero), the requested width,
     * and non-reproducing across two requests. A `dec` token that regressed to the pre-fix hex fall-through
     * would fail the all-digits assertion here (0x`-hex` includes a-f). N=16 → ~53 bits (dec ≈ 3.3 bits/
     * char), so A != B cannot flake.
     */
    public function test_armed_dec_token_is_digits_correct_length_and_non_reproducing(): void
    {
        $r = new RequestContext('GET', '/x', 'probe=1');
        $em = $this->emulator($this->rule('{{volatile.errref:dec:16}}'), true);

        $a = $this->tokenSpan($em->emulate($r, 7)->body);
        $b = $this->tokenSpan($em->emulate($r, 7)->body);

        // All-digits, leading digit non-zero, exactly 16 chars — the fake `dec` character class/shape.
        self::assertSame(1, preg_match('/^[1-9][0-9]{15}$/', $a), "armed dec token '{$a}' is not a 16-digit field");
        self::assertSame(1, preg_match('/^[1-9][0-9]{15}$/', $b), "armed dec token '{$b}' is not a 16-digit field");
        // Non-reproducing (16 dec digits ≈ 53 bits; flake ~2^-53).
        self::assertNotSame($a, $b, 'armed dec proof token must not reproduce');
    }

    /**
     * ARMED == OFF character class for `dec`: the OFF path delegates to {{fake.errref:dec}} (all-digits),
     * so an armed `dec` token must sit in the SAME character class as the off one — the fix closes the
     * latent trap where armed `dec` served hex (a-f) while off served digits. (Values differ — armed is
     * fresh entropy, off is the seeded fake — only the char class is asserted equal.)
     */
    public function test_armed_dec_matches_off_character_class(): void
    {
        $r = new RequestContext('GET', '/x', 'probe=1');

        $off = $this->tokenSpan($this->emulator($this->rule('{{volatile.errref:dec:16}}'), false)->emulate($r, 7)->body);
        $armed = $this->tokenSpan($this->emulator($this->rule('{{volatile.errref:dec:16}}'), true)->emulate($r, 7)->body);

        // OFF path (fake delegate) is all-digits...
        self::assertSame(1, preg_match('/^[1-9][0-9]{15}$/', $off), "off dec token '{$off}' is not a 16-digit field");
        // ...and ARMED is the SAME character class (not hex).
        self::assertSame(1, preg_match('/^[1-9][0-9]{15}$/', $armed), "armed dec token '{$armed}' must share the off char class");
    }

    /**
     * ARMED `b64` (fable nit #1): the b64 branch had no direct armed-path test. Assert the shape is the
     * b64 alphabet ([A-Za-z0-9+/], no CR/LF/NUL), the requested width, and non-reproducing with large N.
     */
    public function test_armed_b64_token_is_shape_safe_and_non_reproducing(): void
    {
        $r = new RequestContext('GET', '/x', 'probe=1');
        $em = $this->emulator($this->rule('{{volatile.errref:b64:22}}'), true);

        $bodyA = $em->emulate($r, 7)->body;
        $bodyB = $em->emulate($r, 7)->body;
        $a = $this->tokenSpan($bodyA);
        $b = $this->tokenSpan($bodyB);

        // No control bytes anywhere in the served body.
        self::assertSame(0, preg_match('/[\r\n\x00]/', $bodyA), 'control byte in armed b64 body');
        // b64 alphabet, exactly 22 chars.
        self::assertSame(1, preg_match('#^[A-Za-z0-9+/]{22}$#', $a), "armed b64 token '{$a}' violates shape/length");
        self::assertSame(1, preg_match('#^[A-Za-z0-9+/]{22}$#', $b), "armed b64 token '{$b}' violates shape/length");
        // Non-reproducing (22 b64 chars ≈ 132 bits).
        self::assertNotSame($a, $b, 'armed b64 proof token must not reproduce');
    }

    // --- position-blind: the volatile path ignores $r ----------------------------------------------

    /**
     * The armed volatile path draws from entropy, not the request, so renderRule with $r=null still mints
     * a token (and a distinct one each call) — no accidental coupling to the request.
     */
    public function test_position_blind_port(): void
    {
        $em = $this->emulator($this->rule(), true);
        $captures = ['probe=1'];

        $port1 = $em->renderRule($this->rule(), $captures, 7, null);
        $port2 = $em->renderRule($this->rule(), $captures, 7, null);
        self::assertNotNull($port1);
        self::assertNotNull($port2);
        self::assertNotSame($this->token($port1->body), $this->token($port2->body), 'armed token minted with $r=null and non-reproducible');
    }

    // --- compiler acceptance ----------------------------------------------------------------------

    public function test_compiler_accepts_volatile_directive_and_rejects_typo(): void
    {
        // volatile. is in the closed vocabulary → compiles.
        $rules = $this->compileOne(<<<'YAML'
id: volatile-compile
severity: medium
tags: [test]
status: 500
match:
  - in: query
    regex: 'probe=1'
response:
  headers: { Content-Type: "text/html; charset=utf-8" }
  body: "ref {{volatile.errref:hex:16}}"
expect: ["ref "]
YAML);
        self::assertCount(1, $rules);
        self::assertStringContainsString('{{volatile.errref:hex:16}}', (string) $rules[0]['response']['body']);

        // The compiled rule is a pure array literal (no non-literal snuck into the artifact).
        $php = "<?php\n\nreturn " . var_export($rules, true) . ";\n";
        self::assertTrue((new PhpLiteralValidator())->isValid($php), 'compiled volatile rule must be a pure array literal');

        // A typo of the prefix is NOT in the closed vocabulary → build fails.
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: volatile-typo
severity: medium
tags: [test]
status: 500
match:
  - in: query
    regex: 'probe=1'
response:
  body: "ref {{voltile.errref:hex:16}}"
YAML);
    }

    /** The shipped demonstrator rule is present in the compiled attack artifact and carries the directive. */
    public function test_demonstrator_rule_compiled(): void
    {
        $rules = require __DIR__ . '/../resources/compiled/funnypot-attack.php';
        $found = null;
        foreach ($rules as $rule) {
            if (($rule['id'] ?? '') === 'attack-verbose-error-volatile') {
                $found = $rule;
                break;
            }
        }
        self::assertNotNull($found, 'attack-verbose-error-volatile must be compiled');
        self::assertStringContainsString('{{volatile.errref:hex:16}}', (string) $found['response']['body']);
        self::assertStringContainsString('{{persona.company.name}}', (string) $found['response']['body']);
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function compileOne(string $yaml): array
    {
        $dir = sys_get_temp_dir() . '/funnypot-volatile-' . getmypid() . '-' . uniqid();
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
