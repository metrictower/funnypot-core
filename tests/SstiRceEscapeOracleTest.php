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
 * FP-0433: SSTI sandbox-escape -> synthetic OS execution oracle. A template-injection that breaks out to OS
 * command exec (Python __subclasses__/__globals__/popen, Java Runtime/ProcessBuilder/Freemarker Execute,
 * PHP |filter('system'), Node child_process, Ruby %x) now gets believable canned OS output (uid=0(root) /
 * Linux) instead of a 404 or a bare ParseError, so the tool confirms RCE. Canned only — zero host exec, no
 * attacker byte reflected, never 500. A plain arithmetic SSTI probe still goes to the numeric oracle.
 */
final class SstiRceEscapeOracleTest extends TestCase
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

    public function test_escape_vectors_yield_canned_command_output(): void
    {
        // SCOPE: the Python object-graph/globals chains, Node breakouts, and Ruby %x that TODAY fall to 404.
        // The Twig filter('system') / Freemarker Execute / Java Runtime escapes stay with 52-ssti-engine-error
        // (FP-0476's deliberate sandboxed-ParseError posture) — asserted separately below.
        $vectors = [
            "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__base__.__subclasses__()[0].__init__.__globals__['sys'].modules['os'].popen('id')}}",
            "{{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
            '<%= %x(id) %>',
        ];
        foreach ($vectors as $pl) {
            $r = $this->probe($pl);
            self::assertSame(200, $r->status, "{$pl} must be 200, never 5xx");
            self::assertSame('attack-ssti-rce-escape', $r->servedBy->ruleId ?? null, "{$pl} must hit the RCE-escape oracle");
            self::assertStringContainsString('uid=0(root)', (string) $r->body, "{$pl} must return canned id output");
        }
    }

    public function test_twig_freemarker_java_escapes_stay_with_the_sandboxed_parse_error(): void
    {
        // FP-0476 posture preserved: these engines present as SANDBOXED (ParseException), NOT exploitable.
        // Flipping them to exploitable is a deploy-posture decision deferred to FP-0577.
        foreach (['{{[1]|filter("system")}}', '#set($x=$class.forName("java.lang.Runtime"))$x'] as $pl) {
            self::assertSame('attack-ssti-engine-error', $this->probe($pl)->servedBy->ruleId ?? null, "{$pl} must stay 52's ParseError (FP-0476 posture)");
        }
    }

    public function test_os_discovery_returns_a_synthetic_platform(): void
    {
        $r = $this->probe("{{config.__class__.__init__.__globals__['os'].popen('uname -a').read()}}");
        self::assertSame('attack-ssti-rce-escape', $r->servedBy->ruleId ?? null);
        self::assertStringContainsString('Linux', (string) $r->body);
        self::assertStringNotContainsString('uid=0', (string) $r->body, 'a uname probe returns the platform, not id output');
    }

    public function test_passwd_read_via_escape_serves_passwd_content(): void
    {
        // Whether answered by this oracle or the LFI decoy, the escape that cats /etc/passwd must leak passwd.
        $r = $this->probe("{{['cat /etc/passwd']|filter('system')}}");
        self::assertSame(200, $r->status);
        self::assertStringContainsString('root:x:0:0:', (string) $r->body, 'the passwd-read escape must leak synthetic /etc/passwd');
    }

    public function test_plain_ssti_probes_are_unaffected(): void
    {
        self::assertSame('attack-ssti-numeric', $this->probe('{{7*7}}')->servedBy->ruleId ?? null, 'a plain arithmetic SSTI still renders via the numeric oracle');
    }

    public function test_no_attacker_byte_reflected_and_fingerprint_safe(): void
    {
        $r = $this->probe("{{''.__class__.__subclasses__()['ZCANARYZ'].popen('id')}}");
        self::assertStringNotContainsString('ZCANARYZ', (string) $r->body, 'the escape output is canned, never the raw payload');
        for ($s = 0; $s < 200; $s++) {
            $b = (string) $this->probe("{{''.__class__.__mro__[1].__subclasses__()[0]('id')}}", (string) $s)->body;
            self::assertStringContainsString('uid=0(root)', $b, "seed {$s} marker");
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} denylist run");
        }
    }
}
