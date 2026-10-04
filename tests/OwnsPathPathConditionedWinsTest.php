<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0547: on an owns_path-claimed path, a path-conditioned rule (the owner + path-coherent siblings)
 * wins over a path-agnostic generic injection rule whose window is the exploit BODY. Tests are at the
 * classify()/respond() level (the override site), not emulate() — which does not route through the
 * override — plus one emulator-level assertion isolating the two-tier promotion.
 */
final class OwnsPathPathConditionedWinsTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(string $ceiling = 'critical'): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, $ceiling, 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
    }

    public function test_emulator_two_tier_promotes_path_conditioned_over_generic(): void
    {
        // TeamCity owns /hax (priority 54, has in:path); the generic LFI rule (priority 31, in:request,
        // no in:path) also matches a /etc/passwd-bearing body. Plain matchRule returns the lower-priority
        // generic; matchOnOwnedPath promotes the path-conditioned owner.
        $r = new RequestContext('POST', '/hax', 'jsp=/app/rest/server;.jsp', [], 'x=/etc/passwd', 'x.test');
        $generic = $this->emulator()->matchRule($r);
        $owned = $this->emulator()->matchOnOwnedPath($r);

        self::assertNotNull($generic);
        self::assertNotNull($owned);
        self::assertSame('attack-teamcity-cve-2024-27198', (string) $owned['rule']['id'], 'owned-path scan picks the path owner');
        self::assertNotSame('attack-teamcity-cve-2024-27198', (string) $generic['rule']['id'], 'plain matchRule picks the lower-priority generic (the bug)');
        // The generic winner is genuinely path-agnostic (no in:path) — i.e. Tier 2.
        $hasPath = false;
        foreach ((array) ($generic['rule']['match'] ?? []) as $cond) {
            if (($cond['in'] ?? 'request') === 'path') { $hasPath = true; }
        }
        self::assertFalse($hasPath, 'the shadowing generic rule carries no in:path condition');
    }

    public function test_classify_serves_the_path_owner_not_the_generic_lfi(): void
    {
        // The override site (classify/respond) must use matchOnOwnedPath: /hax with an LFI body serves the
        // TeamCity XML, never the generic passwd page.
        $resp = $this->engine()->respond(new RequestContext('POST', '/hax', 'jsp=/app/rest/server;.jsp', [], 'x=/etc/passwd', 'x.test'));
        $body = $resp !== null ? (string) $resp->body : '';
        self::assertStringContainsString('buildNumber', $body, 'TeamCity owner serves on its path');
        self::assertStringNotContainsString('root:x:0:0', $body, 'the generic LFI passwd page must NOT win on the owned path');
    }

    public function test_tier2_fallback_preserves_generic_decoy_on_decline(): void
    {
        // Owner 35-wp-admin-ajax declines (no action token); no other in:path rule matches admin-ajax.php,
        // so Tier 1 is empty and the path-agnostic 38-webshell-upload-multipart (Tier 2) still serves —
        // today's behavior, preserved by the fallback.
        $boundary = '----WebKitFormBoundaryABC';
        $body = "--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
            . "Content-Type: application/x-php\r\n\r\n<?php echo 1; ?>\r\n--$boundary--\r\n";
        $resp = $this->engine()->respond(new RequestContext('POST', '/wp-admin/admin-ajax.php', '',
            ['Content-Type' => "multipart/form-data; boundary=$boundary"], $body, 'x.test'));
        $b = $resp !== null ? (string) $resp->body : '';
        self::assertStringContainsString('"success"', $b, 'the webshell-upload decoy still serves via the Tier-2 fallback');
    }

    public function test_decline_falls_through_when_nothing_matches(): void
    {
        // Owned /hax, but no jsp= (owner declines) and no injection payload (no generic matches) -> both
        // tiers empty -> matchOnOwnedPath null -> the override declines to the static bundle (not the
        // TeamCity attack verdict).
        $resp = $this->engine()->respond(new RequestContext('GET', '/hax', '', [], null, 'x.test'));
        $body = $resp !== null ? (string) $resp->body : '';
        // The owner's ATTACK XML carries the affected version literal 2023.11.3; the fall-through static
        // detection stub does not. Absence of that literal proves the override declined (fell through),
        // while the stub's own witness words (buildNumber/internalId) remain.
        self::assertStringNotContainsString('2023.11.3', $body, 'no jsp= -> TeamCity owner declines -> no attack XML serve');
    }

    public function test_gated_owner_closed_still_serves_the_generic_attack(): void
    {
        // FP-0547 review F1: /wp-json is owned by woo-wp-json-index, which is persona-gated (route-woo-store).
        // On the default (non-woo) seed that gate is CLOSED, so the gate-aware scan skips the owner and
        // continues to the ungated generic LFI rule — the request keeps its ATTACK_CLASS serve instead of
        // being downgraded to the static index. A benign /wp-json still serves the static index.
        $attack = $this->engine()->respond(new RequestContext('GET', '/wp-json', 'f=../.ssh/id_rsa', [], null, 'x.test'));
        $ab = $attack !== null ? (string) $attack->body : '';
        self::assertStringContainsString('BEGIN', $ab, 'a gated-closed owner must not suppress the generic LFI attack serve');

        $benign = $this->engine()->respond(new RequestContext('GET', '/wp-json', '', [], null, 'x.test'));
        $bb = $benign !== null ? (string) $benign->body : '';
        self::assertStringNotContainsString('BEGIN', $bb, 'benign /wp-json serves the static index, not an attack decoy');
    }

    public function test_override_site_calls_matchOnOwnedPath(): void
    {
        // Source pin: the owns_path override must route through matchOnOwnedPath so a refactor cannot
        // silently revert to matchRule (which reopens the path-agnostic-shadows-owner bug, FP-0547).
        $src = file_get_contents(__DIR__ . '/../src/Honeypot.php');
        self::assertNotFalse($src);
        // The override calls matchOnOwnedPath with the request and a persona-gate predicate (gate-aware
        // scan, review F1). Pin the call so a refactor can't revert to the shadow-prone matchRule here.
        self::assertStringContainsString('matchOnOwnedPath($r,', $src);
    }
}
