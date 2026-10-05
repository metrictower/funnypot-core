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
 * FP-0546: Velocity / FreeMarker arithmetic RENDER oracle. An assign-then-render probe (Velocity
 * #set($c=7*7)${c} / #set($x=7*7)$x, FreeMarker <#assign x=7*7>${x}) now reflects the computed integer (49)
 * via the SafeArithmetic expr-eval behavior — a real engine would render it — instead of 52-ssti-engine-
 * error's canned ParseException, which stays for the non-numeric escape/directive probes. No attacker byte
 * reflected (pure digits), never 500.
 */
final class SstiVelocityFreeMarkerOracleTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;
    /** @var array<string,Honeypot> */
    private static $engines = [];

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (isset(self::$engines[$seed])) {
            return self::$engines[$seed];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return self::$engines[$seed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function probe(string $payload, string $seed = 'fixed'): object
    {
        $r = $this->engine($seed)->respond(new RequestContext('GET', '/p.php', 'x=' . rawurlencode($payload), [], null, 'x.test'));
        self::assertNotNull($r);

        return $r;
    }

    public function test_velocity_and_freemarker_render_probes_reflect_the_product(): void
    {
        $cases = [
            '#set($c=7*7)${c}' => '49',
            '#set($x=7*7)$x' => '49',
            '<#assign x=7*7>${x}' => '49',
            '#set($v=1338-1)$v' => '1337',
            '<#assign n=100/4>${n}' => '25',
        ];
        foreach ($cases as $payload => $want) {
            $r = $this->probe($payload);
            self::assertSame(200, $r->status, "{$payload} must be 200");
            self::assertSame('attack-ssti-velocity-freemarker', $r->servedBy->ruleId ?? null, "{$payload} must hit the arith oracle");
            self::assertSame($want, trim((string) $r->body), "{$payload} must render {$want} (computed, not canned)");
        }
    }

    public function test_randomised_operands_prove_real_computation(): void
    {
        // A canned 49 could never fake a random operand pair.
        self::assertSame('391', trim((string) $this->probe('#set($v=17*23)$v')->body));
        self::assertSame('0', trim((string) $this->probe('<#assign z=41-41>${z}')->body));
    }

    public function test_non_numeric_probes_still_get_the_parse_error(): void
    {
        // An escape / object-access / string directive does not match the arithmetic grammar, so it falls
        // through to 52-ssti-engine-error's canned engine ParseException (unchanged).
        foreach (['#set($x=$class.forName("java.lang.Runtime"))$x', '<#assign x="foo">${x}'] as $payload) {
            $r = $this->probe($payload);
            self::assertSame('attack-ssti-engine-error', $r->servedBy->ruleId ?? null, "{$payload} must stay the ParseError oracle");
        }
    }

    public function test_div_by_zero_declines_to_base_never_5xx(): void
    {
        $r = $this->probe('#set($v=7/0)$v');
        self::assertSame('attack-ssti-velocity-freemarker', $r->servedBy->ruleId ?? null);
        self::assertLessThan(500, $r->status, 'a div-by-zero arith probe must decline to the base page, never 500');
        self::assertStringNotContainsString('7/0', (string) $r->body, 'the declined probe reflects nothing');
    }

    public function test_result_is_pure_digits_no_attacker_byte_reflected(): void
    {
        $r = $this->probe('#set($c=7*ZCANARYZ)${c}'); // non-arith -> should NOT render a product
        self::assertStringNotContainsString('ZCANARYZ', (string) $r->body, 'a non-arith operand never reflects the raw payload');
        // a valid arith render is digits only
        $body = trim((string) $this->probe('#set($c=12*12)${c}')->body);
        self::assertSame('144', $body);
        self::assertSame(1, preg_match('/^\d+$/', $body), 'the rendered value is pure digits');
    }
}
