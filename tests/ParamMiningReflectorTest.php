<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Closure;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Reaction\ParamIntent;
use Funnypot\Core\Reaction\ParamMiningProbe;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0427: parameter-mining canary reflector for sqlmap --mine-params. A mining batch (>=12 params whose
 * value is a `^[a-z]{10}$` canary) that includes a designated honey-key (debug/cfg) gets ONLY that honey-key's
 * canary echoed verbatim into the body, so sqlmap's substring reflection test (canary in page AND canary not
 * in baseline) confirms ONLY the honey-parameter and pours its SQLi testing into the differential tarpit.
 * Gated like every reaction intent (paramReactivity && serveReflector('param-reaction') => isolatedOrigin +
 * authorizer): it NEVER fires on an embedded host.
 */
final class ParamMiningReflectorTest extends TestCase
{
    private const CANARY = 'zxcvbnmasd';            // a sqlmap-shaped canary: 10 lowercase letters
    private const DECORATABLE = '/admin';           // a non-root text/html route the decorator can inject into

    /** @var array<string,mixed>|null */
    private static $idx;

    private static function idx(): array
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$idx;
    }

    private function engine(bool $isolated, ?Closure $authorizer, bool $paramReactivity = true): Honeypot
    {
        $cfg = new Config(
            mode: 'respond',
            gate: static function (RequestContext $r): bool { return true; },
            personaSeed: static function (RequestContext $r): string { return 'fixed'; },
            severityCeiling: 'critical',
            paramReactivity: $paramReactivity,
            isolatedOrigin: $isolated,
            reflectorAuthorizer: $authorizer,
        );

        return new Honeypot(new PhpArrayStore(self::idx()), $cfg);
    }

    private static function yes(): Closure
    {
        return static function (RequestContext $r, string $class): bool { return true; };
    }

    /** A sqlmap-style batch of canary-valued params; the honey-key's value is CANARY. */
    private static function batch(string $honeyKey = 'debug'): string
    {
        $names = ['id', 'user', 'page', 'file', 'q', 'url', 'cmd', 'search', 'view', 'token', 'ref', 'lang', 'sort', 'cat', $honeyKey];
        $parts = [];
        foreach ($names as $i => $n) {
            $parts[] = $n . '=' . ($n === $honeyKey ? self::CANARY : substr('abcdefghijklmnopqrst', $i % 10, 10));
        }

        return implode('&', $parts);
    }

    // --- the probe (pure) ------------------------------------------------------------------------

    public function test_probe_detects_batch_with_honey_key(): void
    {
        $i = ParamMiningProbe::detect(self::batch('debug'));
        self::assertNotNull($i);
        self::assertSame(ParamIntent::KIND_DEBUG_CANARY, $i->kind);
        self::assertSame('debug', $i->key);
        self::assertSame(self::CANARY, $i->value);
    }

    public function test_probe_accepts_cfg_honey_key(): void
    {
        $i = ParamMiningProbe::detect(self::batch('cfg'));
        self::assertNotNull($i);
        self::assertSame('cfg', $i->key);
    }

    public function test_probe_declines_below_threshold_no_honey_or_non_canary(): void
    {
        self::assertNull(ParamMiningProbe::detect('debug=' . self::CANARY . '&q=abcdefghij'), 'below threshold');
        self::assertNull(ParamMiningProbe::detect(str_replace('debug=', 'xdebug=', self::batch())), 'no honey key present');
        self::assertNull(ParamMiningProbe::detect('debug=1&q=hello&x=y'), 'debug=1 is not a canary batch');
        // A honey key whose value is NOT canary-shaped (even in a full batch) is not confirmed.
        self::assertNull(ParamMiningProbe::detect(str_replace('debug=' . self::CANARY, 'debug=ADMIN', self::batch())), 'honey value must be ^[a-z]{10}$');
    }

    // --- end-to-end reflection + safety gate -----------------------------------------------------

    private function body(Honeypot $hp, string $query): string
    {
        $r = $hp->respond(new RequestContext('GET', self::DECORATABLE, $query, [], null, 'x.test'));

        return $r === null ? '' : (string) $r->body;
    }

    public function test_isolated_authorized_reflects_the_honey_canary(): void
    {
        $body = $this->body($this->engine(true, self::yes()), self::batch());
        self::assertStringContainsString(self::CANARY, $body, 'the honey canary must reflect verbatim (sqlmap confirms it)');
    }

    public function test_baseline_without_the_batch_lacks_the_canary(): void
    {
        // sqlmap also requires "canary not in base" — the canary-free render of the same route must not carry it.
        $base = $this->body($this->engine(true, self::yes()), '');
        self::assertStringNotContainsString(self::CANARY, $base, 'baseline must not contain the canary');
    }

    public function test_only_the_honey_canary_is_reflected(): void
    {
        $body = $this->body($this->engine(true, self::yes()), self::batch());
        // The non-honey candidates' values are never echoed, so sqlmap confirms only the honey-param.
        self::assertStringNotContainsString('abcdefghij', $body, 'a non-honey canary must not appear in the body');
    }

    public function test_embedded_host_never_reflects(): void
    {
        $body = $this->body($this->engine(false, self::yes()), self::batch());
        self::assertStringNotContainsString(self::CANARY, $body, 'an embedded host must never reflect the canary');
    }

    public function test_isolated_without_authorizer_is_withheld(): void
    {
        $body = $this->body($this->engine(true, null), self::batch());
        self::assertStringNotContainsString(self::CANARY, $body, 'no authorizer evidence => withheld');
    }

    public function test_param_reactivity_off_is_withheld(): void
    {
        $body = $this->body($this->engine(true, self::yes(), false), self::batch());
        self::assertStringNotContainsString(self::CANARY, $body, 'paramReactivity off => no reaction at all');
    }

    public function test_reflected_body_is_fingerprint_safe(): void
    {
        for ($s = 0; $s < 50; $s++) {
            $cfg = new Config(
                mode: 'respond',
                gate: static function (RequestContext $r): bool { return true; },
                personaSeed: static function (RequestContext $r): string { return 'fixed'; },
                severityCeiling: 'critical',
                paramReactivity: true,
                isolatedOrigin: true,
                reflectorAuthorizer: self::yes(),
                deploySeed: (string) $s,
            );
            $hp = new Honeypot(new PhpArrayStore(self::idx()), $cfg);
            $body = $this->body($hp, self::batch());
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $body), "deploy {$s} denylist run");
        }
    }
}
