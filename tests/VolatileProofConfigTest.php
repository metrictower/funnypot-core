<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0232 — the Config::$volatileProof arm and its end-to-end wiring. $volatileProof is additive-only:
 * off by default, appended at the very END of the Config ctor (S1) so every existing positional caller
 * is unaffected. The wiring proof drives a REAL Honeypot (Config → Honeypot → TemplateAttackEmulator ::
 * fromPackage → DirectiveRenderer ctor — the real consumer, one hop past $promptInjectionSeeding) so a
 * dead-wiring regression (which this repo has bounced plans for) fails loudly.
 */
final class VolatileProofConfigTest extends TestCase
{
    // --- the arm ----------------------------------------------------------------------------------

    public function test_defaults_to_false(): void
    {
        self::assertFalse((new Config())->volatileProof);
    }

    public function test_property_assignment_exposes_the_value(): void
    {
        $c = new Config();
        $c->volatileProof = true;
        self::assertTrue($c->volatileProof);
    }

    /** volatileProof sits at the very END of the ctor — pass every positional arg to prove placement. */
    public function test_ctor_arg_at_end_exposes_the_value(): void
    {
        $c = new Config(
            'detect', null, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0,
            false, null, null, null, '', [], true, null, null, null, null, null, [], false, false, null,
            true /* volatileProof */
        );
        self::assertTrue($c->volatileProof);
    }

    /** Existing positional callers that stop before the new arg keep constructing, arm defaulting off. */
    public function test_preexisting_positional_usage_still_constructs(): void
    {
        $c = new Config('respond', null, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0, false, null, null, null, '', []);
        self::assertSame('respond', $c->mode);
        self::assertFalse($c->volatileProof);
    }

    // --- end-to-end wiring through a real Honeypot ------------------------------------------------

    /** A full Honeypot over the REAL compiled corpus, respond mode + permissive gate + attackEmulation. */
    private function engine(bool $armed): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only', null, 'coherent', Style::MINIMAL,
            'high', 65536, 0, 0, true /* attackEmulation */
        );
        $config->volatileProof = $armed;

        return new Honeypot($store, $config);
    }

    /** The demonstrator's error-reference proof token from a served body. */
    private function token(string $body): string
    {
        self::assertSame(1, preg_match('/Error reference: ([0-9a-f]{16})</', $body, $m), "no proof token in served body: {$body}");

        return $m[1];
    }

    /** The demonstrator probe: a hex value where an integer is expected trips the verbose-error decoy. */
    private function probe(): RequestContext
    {
        return new RequestContext('GET', '/', 'offset=0x1a2b');
    }

    public function test_off_serves_a_stable_proof_token_across_identical_requests(): void
    {
        $engine = $this->engine(false);
        $a = $engine->respond($this->probe());
        $b = $engine->respond($this->probe());
        self::assertNotNull($a, 'demonstrator must serve');
        self::assertNotNull($b);
        self::assertStringContainsString('Application error', $a->body);
        self::assertSame($a->body, $b->body, 'arm OFF ⇒ identical probes are byte-identical (stable proof)');
    }

    public function test_armed_serves_a_non_reproducible_proof_token_but_stable_identity(): void
    {
        $engine = $this->engine(true);
        $a = $engine->respond($this->probe());
        $b = $engine->respond($this->probe());
        self::assertNotNull($a, 'demonstrator must serve when armed');
        self::assertNotNull($b);

        // The proof token differs (non-reproducible), while the surrounding identity/structure is stable.
        self::assertNotSame($this->token($a->body), $this->token($b->body), 'arm ON ⇒ proof token must not reproduce');

        $mask = static function (string $body): string {
            return (string) preg_replace('/Error reference: [0-9a-f]{16}</', 'Error reference: <TOKEN><', $body);
        };
        self::assertSame($mask($a->body), $mask($b->body), 'only the proof token mutates — identity + structure stay byte-stable');
    }
}
