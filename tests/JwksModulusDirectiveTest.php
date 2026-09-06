<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Compiler\ParamRouteCompiler;
use Funnypot\Core\Compiler\RouteEmulatorCompiler;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * FP-0274 — the closed JWKS RSA-modulus form {{fake.jwks_n:rsa2048:342}}.
 *
 * A plain b64url:342 token decodes to 256 bytes but is a coin-flip even and often < 2048 bits — a
 * manual tell for a crypto-literate analyst reading /.well-known/jwks.json. The rsa2048 form forces
 * the two boundary bits every real RSA modulus carries (top bit of byte 0, low bit of byte 255), so
 * `n` is always a 2048-bit odd integer. The form is CLOSED: it is legal only as this exact name and
 * length, and only as a {{fake.*}} directive — never {{volatile.*}} (which the OFF arm would delegate
 * to the fake path). Every generic {{fake.*:b64url:N}} value is untouched (byte-identical golden
 * vectors), so the boundary-bit change is scoped to the one JWKS cell.
 */
final class JwksModulusDirectiveTest extends TestCase
{
    /** Strict URL-safe base64 decode with restored padding — returns the raw modulus bytes. */
    private static function b64urlDecode(string $s): string
    {
        $t = strtr($s, '-_', '+/');
        $t .= str_repeat('=', (4 - strlen($t) % 4) % 4);

        return (string) base64_decode($t, true);
    }

    // --- the modulus invariants: 256 bytes, 2048-bit, odd, over a wide seed sweep -----------

    public function test_modulus_is_a_256_byte_2048_bit_odd_integer_across_seeds(): void
    {
        $rr = new DirectiveRenderer();
        for ($seed = 0; $seed <= 1023; $seed++) {
            $n = $rr->render('{{fake.jwks_n:rsa2048:342}}', [], $seed);
            // Unpadded URL-safe base64 alphabet, exactly 342 chars.
            self::assertSame(342, strlen($n), "seed {$seed}: modulus must be 342 chars");
            self::assertSame(1, preg_match('#^[A-Za-z0-9_-]{342}$#', $n), "seed {$seed}: b64url alphabet only, no padding");

            $raw = self::b64urlDecode($n);
            self::assertSame(256, strlen($raw), "seed {$seed}: modulus must decode to exactly 256 bytes");
            // Top bit of byte 0 set ⇒ the unsigned big-endian integer is a full 2048 bits.
            self::assertSame(0x80, ord($raw[0]) & 0x80, "seed {$seed}: top bit must be set (2048-bit)");
            // Low bit of byte 255 set ⇒ the integer is odd.
            self::assertSame(0x01, ord($raw[255]) & 0x01, "seed {$seed}: low bit must be set (odd)");
        }
    }

    public function test_modulus_is_deterministic_and_seed_varying(): void
    {
        $rr = new DirectiveRenderer();
        // Repeat + order independence: same (renderer, seed) reproduces byte-for-byte.
        $a = $rr->render('{{fake.jwks_n:rsa2048:342}}', [], 7);
        $b = $rr->render('{{fake.jwks_n:rsa2048:342}}', [], 7);
        self::assertSame($a, $b);
        self::assertSame($a, (new DirectiveRenderer())->render('{{fake.jwks_n:rsa2048:342}}', [], 7));
        // Distinct seeds give distinct moduli (no fixed scaffold across deploys).
        self::assertNotSame($a, $rr->render('{{fake.jwks_n:rsa2048:342}}', [], 8));
    }

    /** Pinned golden moduli — freeze the exact derivation so a silent drift is caught. */
    public function test_modulus_pinned_golden_values(): void
    {
        $rr = new DirectiveRenderer();
        self::assertSame(
            'tn1REBHgRf72pllrrJ9LTLp-rxvjWkCA1AmPXJCGlRbX4HILjURWJqex8uGywFcBvZ9rlkrDbRqVURlhq5iJezaYX_-eleLn5qtR41Jzf3AXCm3Fk1bMdoVTbcDpwLeCmV3lEvFyQApR0MyOx6rnza_NbriDunIpyLy0-WBeiKgbZSrZeIGBmdLZMtbDNst24Pgw1KlAav1qqwc1YWQ0CnNb1kP4bBzL70YXUKFhTm2ZtIKxocyxybHW-z4tOUjvB52lWkOeuA0ey-fCiIONkOiIcEYQkLRCU0w9eUAV2yiemwAurfYI4euHd-LJ1wvTGqmaWqYS_o-fOOHrc8sBtw',
            $rr->render('{{fake.jwks_n:rsa2048:342}}', [], 0)
        );
        self::assertSame(
            'n0mriWizpTYxzgLuzOwrcVu3Fc5hymgrsrLTNpLWMbNgVuzg9AvZEDxJMpSv6CPMl2nkJHXxkzRqKw0wie1UR7TFcFUoM0QTUMpYY8a9Z4zvSO_lkWDp0tQ-FIMKtkivyszjzP7MeMLEN-xZuJ-cmv_47kc_qM2HABJXUsFn_gKtegZoBPO44EvkS77aBKkGhR4gW_h3hYv-WsAfRnnyRkr4etMBsQlntUM2in_StROn56o33PKFvj_nIjwfrG-tN8FoetSv3TLx3ggS4NovekLvY7c_2G3vzBeiejQjMfUNrvhQXy5RLxAyGPJsX-wDEuZbEenJd9618sIepVyQ-w',
            $rr->render('{{fake.jwks_n:rsa2048:342}}', [], 1)
        );
    }

    /**
     * The rsa2048 output differs from a b64url:342 render of the SAME name/seed ONLY in the two forced
     * boundary bits — proof that the generic b64url derivation is untouched and the change is the two
     * bits, nothing else.
     */
    public function test_modulus_differs_from_b64url_only_in_boundary_bits(): void
    {
        $rr = new DirectiveRenderer();
        for ($seed = 0; $seed <= 64; $seed++) {
            $b64 = self::b64urlDecode($rr->render('{{fake.jwks_n:b64url:342}}', [], $seed));
            $rsa = self::b64urlDecode($rr->render('{{fake.jwks_n:rsa2048:342}}', [], $seed));
            self::assertSame(256, strlen($b64));
            $expected = $b64;
            $expected[0] = $expected[0] | "\x80";
            $expected[255] = $expected[255] | "\x01";
            self::assertSame($expected, $rsa, "seed {$seed}: rsa2048 must equal b64url with only the two boundary bits forced");
        }
    }

    // --- generic {{fake.*:b64url:N}} stays byte-identical (non-regression golden vectors) ----

    public function test_generic_b64url_vectors_are_byte_identical(): void
    {
        $rr = new DirectiveRenderer();
        // Frozen vectors under an ORDINARY name; rsa2048 must not perturb any generic b64url render.
        self::assertSame('JoGmc0hEmHRfqLZFRV-gN3', $rr->render('{{fake.tok:b64url:22}}', [], 0));
        self::assertSame('JoGmc0hEmHRfqLZFRV-gN3BKxgAstjeU9uAhiBjjTrs', $rr->render('{{fake.tok:b64url:43}}', [], 0));
        self::assertSame('JoGmc0hEmHRfqLZFRV-gN3BKxgAstjeU9uAhiBjjTrsv', $rr->render('{{fake.tok:b64url:44}}', [], 0));
        self::assertSame(
            'JoGmc0hEmHRfqLZFRV-gN3BKxgAstjeU9uAhiBjjTrsvmnO8BO5PC-hLiJ-HH4kxpXqKjLLn39Pz9MxOGXxkmgfjYGuAd99f1X6c',
            $rr->render('{{fake.tok:b64url:100}}', [], 0)
        );
        // A b64url:342 under a name OTHER than jwks_n never gets the boundary bits (parity is free).
        $other = $rr->render('{{fake.tok:b64url:342}}', [], 0);
        self::assertSame(342, strlen($other));
        self::assertSame(1, preg_match('#^[A-Za-z0-9_-]{342}$#', $other));
    }

    /**
     * rsa2048 is scoped to jwks_n:342 at RENDER time too (defence in depth behind the compiler): the
     * same name at another length, or another name at 342, falls to the generic default
     * (substr(64-hex digest, 0, len)), never the 342-char modulus. The compilers reject these shapes,
     * so this only ever matters for a hand-crafted artifact — where the hex default is the safe miss.
     */
    public function test_rsa2048_scoped_to_jwks_n_342_at_render_time(): void
    {
        $rr = new DirectiveRenderer();
        foreach (['{{fake.jwks_n:rsa2048:341}}', '{{fake.other:rsa2048:342}}'] as $directive) {
            $out = $rr->render($directive, [], 0);
            self::assertNotSame(342, strlen($out), "{$directive}: must not produce the 342-char modulus");
            self::assertSame(1, preg_match('#^[0-9a-f]{1,64}$#', $out), "{$directive}: must fall to the hex digest default");
        }
    }

    // --- rsa2048FormError: the shared compiler predicate ------------------------------------

    public function test_form_error_predicate(): void
    {
        // The one valid form passes.
        self::assertNull(DirectiveRenderer::rsa2048FormError('fake.jwks_n:rsa2048:342'));
        self::assertSame('fake.jwks_n:rsa2048:342', DirectiveRenderer::JWKS_MODULUS_DIRECTIVE);
        // No rsa2048 segment ⇒ nothing to check.
        self::assertNull(DirectiveRenderer::rsa2048FormError('fake.tok:b64url:342'));
        self::assertNull(DirectiveRenderer::rsa2048FormError('persona.company.name'));
        self::assertNull(DirectiveRenderer::rsa2048FormError('fake.person.email:k'));
        // Every near-miss is rejected.
        foreach (['fake.jwks_n:rsa2048:341', 'fake.jwks_n:rsa2048:343', 'fake.jwks_n:rsa2048', 'fake.other:rsa2048:342', 'fake.jwks_n:rsa2048:342:x'] as $bad) {
            self::assertNotNull(DirectiveRenderer::rsa2048FormError($bad), "'{$bad}' must be rejected");
        }
        // Volatile use is rejected outright (the OFF arm would delegate it to the fake modulus path).
        self::assertNotNull(DirectiveRenderer::rsa2048FormError('volatile.jwks_n:rsa2048:342'));
    }

    // --- compiler closure: all three compilers reject every non-canonical rsa2048 form -----

    /** Invoke a compiler's private normalize() with a doc, mirroring the other compiler tests. */
    private function normalize(object $compiler, array $doc): array
    {
        $m = new ReflectionMethod($compiler, 'normalize');
        $m->setAccessible(true);

        return $m->invoke($compiler, $doc, 'jwks-modulus-test.yaml');
    }

    /** @return array<int,array{0:object,1:array<string,mixed>}> a (compiler, doc) pair per compiler. */
    private function compilerDocs(string $directive): array
    {
        $body = '{"n":"' . $directive . '"}';
        $resp = ['headers' => ['Content-Type' => 'application/json'], 'body' => $body];

        return [
            [new RouteEmulatorCompiler(), ['id' => 'route-jwks-test', 'match' => ['pid' => ['route-jwks-test']], 'response' => $resp]],
            [new ParamRouteCompiler(), ['id' => 'param-jwks-test', 'param' => ['path' => '/jwks/{p*}'], 'response' => $resp]],
            [new EmulatorCompiler(), ['id' => 'attack-jwks-test', 'match' => [['in' => 'path', 'regex' => '/jwks', 'capture' => false]], 'response' => $resp]],
        ];
    }

    public function test_all_three_compilers_accept_the_canonical_form(): void
    {
        foreach ($this->compilerDocs('{{fake.jwks_n:rsa2048:342}}') as [$compiler, $doc]) {
            // normalize() must not throw for the one valid form (the directive check is the gate here).
            $rule = $this->normalize($compiler, $doc);
            self::assertIsArray($rule, get_class($compiler) . ' must accept the canonical JWKS modulus form');
        }
    }

    /**
     * @dataProvider nearMissProvider
     */
    public function test_all_three_compilers_reject_a_near_miss(string $directive): void
    {
        foreach ($this->compilerDocs($directive) as [$compiler, $doc]) {
            $threw = false;
            try {
                $this->normalize($compiler, $doc);
            } catch (RuntimeException $e) {
                $threw = true;
                // Assert on a phrase from the rsa2048 closure, NOT one echoing the directive text — a
                // generic "unknown directive" reject (or PHPUnit's own fail) would carry the directive
                // string, which itself contains "rsa2048", so matching that would not prove the closure.
                self::assertStringContainsString('JWKS modulus', $e->getMessage(), get_class($compiler) . " must reject '{$directive}' via the rsa2048 closure");
            }
            self::assertTrue($threw, get_class($compiler) . " must reject '{$directive}'");
        }
    }

    /** @return iterable<string,array{0:string}> */
    public static function nearMissProvider(): iterable
    {
        yield 'short length' => ['{{fake.jwks_n:rsa2048:341}}'];
        yield 'long length' => ['{{fake.jwks_n:rsa2048:343}}'];
        yield 'missing length' => ['{{fake.jwks_n:rsa2048}}'];
        yield 'wrong name' => ['{{fake.modn:rsa2048:342}}'];
        yield 'extra segment' => ['{{fake.jwks_n:rsa2048:342:x}}'];
        yield 'volatile use' => ['{{volatile.jwks_n:rsa2048:342}}'];
    }

    // --- the form appears exactly once, only in the registered JWKS template ----------------

    public function test_form_occurs_exactly_once_in_the_templates(): void
    {
        $root = dirname(__DIR__) . '/templates';
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
        $directive = '{{' . DirectiveRenderer::JWKS_MODULUS_DIRECTIVE . '}}';
        $directiveHits = 0;
        $directiveFiles = [];
        foreach ($it as $file) {
            if (!$file->isFile() || substr($file->getFilename(), -5) !== '.yaml') {
                continue;
            }
            $text = (string) file_get_contents($file->getPathname());
            // Any rsa2048 that appears INSIDE a {{...}} directive span must be the canonical form —
            // a plain-word "rsa2048" in a comment is fine, a stray directive shape is not.
            if (preg_match_all('/\{\{[^}]*rsa2048[^}]*\}\}/', $text, $m)) {
                foreach ($m[0] as $span) {
                    self::assertSame($directive, $span, "{$file->getPathname()}: the only rsa2048 directive may be the canonical modulus form");
                }
            }
            $count = substr_count($text, $directive);
            if ($count > 0) {
                $directiveHits += $count;
                $directiveFiles[] = $file->getPathname();
            }
        }
        self::assertSame(1, $directiveHits, 'the rsa2048 modulus directive must appear exactly once across all templates');
        self::assertCount(1, $directiveFiles, 'exactly one template carries the modulus directive: ' . implode(', ', $directiveFiles));
        self::assertStringContainsString('396-jwks-json.yaml', $directiveFiles[0], 'the rsa2048 form belongs to the JWKS route template');
    }
}
