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
 * FP-0477: Spring SpEL / Struts OGNL expression-language RCE oracle. The classic gadgets (SpEL
 * T(java.lang.Runtime).getRuntime().exec, bare OGNL (#rt=@java.lang.Runtime@getRuntime()).exec,
 * ProcessBuilder) that TODAY fall to 404 now get canned OS output (uid=0(root)), so the tool confirms RCE.
 * Scoped to the vectors the existing product-specific rules (attack-struts-ognl / attack-confluence-*) do
 * NOT already own (the fenced ${...}/%{...} Struts/Confluence forms stay with those decoys). Canned only.
 */
final class SpelOgnlRceOracleTest extends TestCase
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

    public function test_bare_spel_and_ognl_gadgets_yield_canned_command_output(): void
    {
        foreach ([
            "T(java.lang.Runtime).getRuntime().exec('id')",
            "(#rt=@java.lang.Runtime@getRuntime()).exec('id')",
            "@java.lang.Runtime@getRuntime().exec('id')",
            "new java.lang.ProcessBuilder(new String[]{'id'}).start()",
        ] as $pl) {
            $r = $this->probe($pl);
            self::assertSame(200, $r->status, "{$pl} must be 200, never 5xx");
            self::assertSame('attack-spel-ognl-rce', $r->servedBy->ruleId ?? null, "{$pl} must hit the SpEL/OGNL oracle");
            self::assertStringContainsString('uid=0(root)', (string) $r->body, "{$pl} must return canned id output");
        }
    }

    public function test_command_branches(): void
    {
        self::assertStringContainsString('root', (string) $this->probe("T(java.lang.Runtime).getRuntime().exec('whoami')")->body);
        self::assertStringContainsString('Linux', (string) $this->probe("@java.lang.Runtime@getRuntime().exec('uname -a')")->body);
    }

    public function test_product_specific_ognl_decoys_still_own_their_surfaces(): void
    {
        // The product-specific rules are path/Content-Type-scoped; on THEIR surfaces they still win (proven
        // authoritatively by AttackLiteralPrefilterTest/ConfluenceModernSuiteTest). Struts OGNL in a
        // Content-Type on /upload.action keeps attack-struts-ognl, not this generic oracle.
        $r = $this->engine()->respond(new RequestContext('POST', '/upload.action', '', ['Content-Type' => "%{(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd))}"], '', 'x.test'));
        self::assertSame('attack-struts-ognl', $r->servedBy->ruleId ?? null, 'Struts OGNL on its own surface stays with its product decoy');
    }

    public function test_plain_arith_el_unaffected(): void
    {
        self::assertSame('attack-ssti-numeric', $this->probe('#{7*7}')->servedBy->ruleId ?? null);
    }

    public function test_no_reflection_and_fingerprint_safe(): void
    {
        $r = $this->probe("T(java.lang.Runtime).getRuntime().exec('ZCANARYZ')");
        self::assertStringNotContainsString('ZCANARYZ', (string) $r->body);
        for ($s = 0; $s < 200; $s++) {
            $b = (string) $this->probe("T(java.lang.Runtime).getRuntime().exec('id')", (string) $s)->body;
            self::assertStringContainsString('uid=0(root)', $b, "seed {$s}");
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} denylist");
        }
    }
}
