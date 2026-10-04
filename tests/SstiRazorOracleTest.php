<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0418: the Razor `@(x*y)` SSTI arithmetic dialect (46-ssti-razor) — the one template style Caido's SSTI
 * math oracle probes that 45-ssti-numeric did not cover. Reflects the SafeArithmetic product (pure digits,
 * html-safe-by-construction); the other six Caido dialects were already covered by 45 (regression-checked).
 */
final class SstiRazorOracleTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $indexCache;

    private function engine(): Honeypot
    {
        if (self::$indexCache === null) {
            self::$indexCache = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', null, 'matched-only', null, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$indexCache), $cfg);
    }

    private function serve(string $payload): string
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/x', 'q=' . rawurlencode($payload), [], null, 'x.test'));

        return $r !== null ? (string) $r->body : '';
    }

    public function test_razor_caido_constant_reflects_the_product(): void
    {
        self::assertStringContainsString((string) (1234 * 5678), $this->serve('@(1234*5678)'), 'Caido SSTI constant');
    }

    public function test_razor_operators(): void
    {
        self::assertSame('49', trim($this->serve('@(7*7)')));
        self::assertSame((string) (90 - 48), trim($this->serve('@(90-48)')));
    }

    public function test_razor_computes_not_echoes(): void
    {
        $b = $this->serve('@(4321*8765)');
        self::assertStringContainsString((string) (4321 * 8765), $b);
        self::assertStringNotContainsString('4321*8765', $b, 'the raw expression must not be echoed');
    }

    public function test_non_arithmetic_razor_reflects_no_product(): void
    {
        // A Razor helper call is not arithmetic -> no product reflected (the rule declines; falls through
        // to an inert page or 404). The key property: no bare computed integer is ever emitted.
        foreach (['@(config)', '@(Html.Raw(x))', '@(User.Name)'] as $p) {
            $b = $this->serve($p);
            self::assertStringNotContainsString('7006652', $b);
            self::assertDoesNotMatchRegularExpression('/^-?\d+\s*$/', trim($b), "{$p} must not reflect a bare product: {$b}");
        }
    }

    public function test_only_digits_reflected_no_markup(): void
    {
        $b = $this->serve('@(11*11)');
        self::assertStringNotContainsString('<', $b);
        self::assertStringNotContainsString('>', $b);
    }

    public function test_the_other_six_caido_dialects_still_covered_by_45(): void
    {
        // Regression: the dialects 45-ssti-numeric owns must keep reflecting the Caido constant.
        foreach (['{{1234*5678}}', '${1234*5678}', '<%= 1234*5678 %>', '{1234*5678}', '[[${1234*5678}]]', '%{1234*5678}'] as $p) {
            self::assertStringContainsString('7006652', $this->serve($p), "45 must still cover {$p}");
        }
    }
}
