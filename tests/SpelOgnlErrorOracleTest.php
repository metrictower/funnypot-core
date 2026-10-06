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
 * FP-0578 (bounded slice): the Spring SpEL / Struts OGNL expression-language ERROR oracle
 * (attack/52b-spel-ognl-error) — the EL twin of 52-ssti-engine-error. An EL-injection FAULT probe
 * (malformed or non-exec SpEL/OGNL in a body/query param) gets the authentic exception a real Spring/
 * Struts app throws (Whitelabel Error Page + SpelEvaluationException, or the Struts Problem Report +
 * ognl.OgnlException), confirming the parameter is EL-evaluated. INERT: authored 500, nothing evaluated,
 * no attacker expression reflected. The exec gadgets (42b) and arithmetic (45) still win first.
 */
final class SpelOgnlErrorOracleTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index;

    private function engine(): Honeypot
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return new Honeypot(
            new PhpArrayStore(self::$index),
            new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
                static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'critical',
                65536, 0, 0, true, null, null, null, 'fixed')
        );
    }

    private function get(string $query): ?object
    {
        return $this->engine()->respond(new RequestContext('GET', '/x', $query, [], null, 'x.test'));
    }

    /** @return array<string,array{0:string}> SpEL fault probes → Spring Whitelabel exception */
    public function spelFaults(): array
    {
        return [
            'type-ref'   => ['name=' . rawurlencode('#{T(java.lang.System).getenv()}')],
            'malformed'  => ['name=' . rawurlencode('#{T(java.lang.Runtime}')],
            'context'    => ['name=' . rawurlencode('#{#this.getClass()}')],
            'sysprops'   => ['name=' . rawurlencode('#{systemProperties["user.dir"]}')],
        ];
    }

    /** @dataProvider spelFaults */
    public function test_spel_fault_serves_spring_exception(string $query): void
    {
        $r = $this->get($query);
        self::assertNotNull($r, 'a SpEL fault probe must serve the Spring exception, not 404');
        self::assertSame(500, $r->status, 'a real Spring app returns 500 for an EL fault');
        self::assertStringContainsString('Whitelabel Error Page', $r->body);
        self::assertStringContainsString('EL1008E', $r->body);
    }

    /** @return array<string,array{0:string}> OGNL fault probes → Struts Problem Report */
    public function ognlFaults(): array
    {
        return [
            'member-access' => ['q=' . rawurlencode('%{(#_memberAccess["allowStaticMethodAccess"]=true)}')],
            'context'       => ['q=' . rawurlencode('%{#context["xwork.MethodAccessor.denyMethodExecution"]}')],
            'dollar-paren'  => ['redirect:' . rawurlencode('${(#x=123)}')],
        ];
    }

    /** @dataProvider ognlFaults */
    public function test_ognl_fault_serves_struts_exception(string $query): void
    {
        $r = $this->get($query);
        self::assertNotNull($r, 'an OGNL fault probe must serve the Struts exception, not 404');
        self::assertSame(500, $r->status);
        self::assertStringContainsString('Struts Problem Report', $r->body);
        self::assertStringContainsString('ognl.OgnlException', $r->body);
    }

    public function test_exec_and_arithmetic_still_win_over_the_error_oracle(): void
    {
        // Precedence: a real exec gadget -> the uid oracle (42b, p42); arithmetic -> 49 (45) — NOT the
        // error page. The error oracle (p51) only catches the faults those miss.
        $exec = $this->get('name=' . rawurlencode("#{T(java.lang.Runtime).getRuntime().exec('id')}"));
        self::assertNotNull($exec);
        self::assertSame(200, $exec->status);
        self::assertStringContainsString('uid=0(root)', $exec->body);
        self::assertStringNotContainsString('Whitelabel', $exec->body);

        $arith = $this->get('name=' . rawurlencode('#{7*7}'));
        self::assertNotNull($arith);
        self::assertStringContainsString('49', $arith->body);
        self::assertStringNotContainsString('Whitelabel', $arith->body);
    }

    /**
     * @dataProvider benignEl
     */
    public function test_benign_expression_fences_are_not_treated_as_el_injection(string $query): void
    {
        // #{home.welcome} (Thymeleaf message), #{user_name} (Ruby interpolation), 100%{discount} (bare
        // percent-brace) carry no EL-injection marker, so the oracle must not fire its exception.
        $r = $this->get($query);
        if ($r !== null) {
            self::assertStringNotContainsString('Whitelabel Error Page', $r->body, "benign must not serve the Spring exception: {$query}");
            self::assertStringNotContainsString('Struts Problem Report', $r->body, "benign must not serve the Struts exception: {$query}");
        } else {
            self::assertNull($r);
        }
    }

    /** @return array<string,array{0:string}> */
    public function benignEl(): array
    {
        return [
            'thymeleaf' => ['name=' . rawurlencode('#{home.welcome}')],
            'ruby'      => ['q=' . rawurlencode('#{user_name}')],
            'pct-brace' => ['q=' . rawurlencode('100%{discount}')],
        ];
    }

    public function test_submitted_expression_is_never_reflected(): void
    {
        $r = $this->get('name=' . rawurlencode('#{T(java.lang.Runtime).CANARYtoken}'));
        self::assertNotNull($r);
        self::assertStringNotContainsString('CANARYtoken', $r->body, 'the exception must not reflect the submitted expression');
    }
}
