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
 * The broad CRS unix-command-injection archetype (`attack-crs-rce`, CRS 932130) treats `$` + `{` as
 * shell-variable interpolation, so a bare `${...}` expression tripped it and the catch-all served a
 * `uid=0(root)` RCE confirmation. But `${...}` is variable EXPANSION or a log4j/JNDI lookup, not unix
 * command EXECUTION — so a `${...}`-only match confirming root is a false positive (benign `${var}`) or an
 * incoherent tell (log4shell: the probe is flagged for intel, but a reflect-only responder must never
 * "respond vulnerable"). The runtime post-filter strips `${...}` and re-runs the rule: a match that depends
 * solely on `${...}` is declined (→ plain 404), while a genuine command (`$(…)`, backtick, or a
 * metacharacter before a command) survives the strip and still confirms.
 */
final class CrsRceDollarExprFalsePositiveTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', null, 'matched-only', null, 'coherent', Style::REALISTIC, 'critical', 65536, 0, 0, false);
        $cfg->isolatedOrigin = true;
        $cfg->attackEmulation = true;
        $cfg->reflectorAuthorizer = static function (RequestContext $r, string $class): bool { return true; };

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function respond(string $path, string $query = ''): ?object
    {
        return $this->engine()->respond(new RequestContext('GET', $path, $query, [], null, 'x.test'), SiteProfile::empty(), 's');
    }

    private function servedBy(?object $r): ?string
    {
        return $r !== null && $r->servedBy !== null ? ($r->servedBy->ruleId ?? null) : null;
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_benign_dollar_expression_does_not_confirm_root(): void
    {
        // A plain ${identifier} — benign templating / shell-variable reference — must NOT serve uid=0, in
        // the path or the query. It falls through to the plain 404 (no attack response at all).
        foreach (['/${benign}', '/${APP_HOME}', '/${foo.bar}', '/a/${x}/b'] as $path) {
            $r = $this->respond($path);
            self::assertNotSame('attack-crs-rce', $this->servedBy($r), $path);
            self::assertStringNotContainsString('uid=0', $this->body($r), $path);
        }
        foreach (['q=${benign}', 'name=${APP_HOME}'] as $q) {
            $r = $this->respond('/x', $q);
            self::assertStringNotContainsString('uid=0', $this->body($r), $q);
        }
    }

    public function test_log4shell_lookup_is_detected_but_never_served_root(): void
    {
        // A log4j/JNDI lookup is a real probe: it must still be DETECTED (threat intel), but the unix-cmdi
        // catch-all must not serve a uid=0 shell confirmation for it (reflect-only cannot fake the OOB hit).
        $path = '/${jndi:ldap://x/a}';
        $r = $this->respond($path);
        self::assertStringNotContainsString('uid=0', $this->body($r), 'log4shell lookup must not serve a root shell confirm');
        self::assertNotSame('attack-crs-rce', $this->servedBy($r));

        $v = $this->engine()->classify(new RequestContext('GET', $path, '', [], null, 'x.test'), SiteProfile::empty());
        self::assertFalse($v->detection->isEmpty(), 'the Log4Shell probe is still detected for intel');
        $ids = array_map(static function ($m) { return is_object($m) ? ($m->id ?? $m->name ?? '') : (string) ($m['id'] ?? ''); }, $v->detection->matches);
        self::assertContains('log4shell-jndi', $ids, 'log4shell detection preserved');
    }

    public function test_genuine_unix_command_injection_still_confirms_root(): void
    {
        // Command substitution, backticks, and metacharacter+command are NOT ${...}; they survive the strip
        // (and are owned by the higher-priority hand-authored cmdi tier) and still confirm uid=0.
        foreach (['/;id', '/$(id)', '/`id`'] as $path) {
            self::assertStringContainsString('uid=0', $this->body($this->respond($path)), $path);
        }
    }

    public function test_dollar_expr_adjacent_to_a_real_command_substitution_still_confirms(): void
    {
        // A benign ${x} next to a real $(id): stripping ${x} leaves $(id), so the match is not suppressed.
        self::assertStringContainsString('uid=0', $this->body($this->respond('/${x}$(id)')), 'mixed ${x}$(id) still confirms');
    }

    public function test_dollar_expr_only_ssti_still_reaches_its_own_tier(): void
    {
        // The strip must not steal a genuine SSTI numeric probe (${7*7}) — it carries no command, so the
        // crs-rce suppression is moot and the dedicated SSTI tier owns it (not a uid=0 confirm anyway).
        $r = $this->respond('/${7*7}');
        self::assertStringNotContainsString('uid=0', $this->body($r), '${7*7} is SSTI, never a root shell');
    }
}
