<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Rules;

use Funnypot\Core\Rules\WafLookalikeGuard;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The WAF-lookalike gate (FP-0363): no served surface may resemble a WAF/antibot challenge or block
 * interstitial. A honeypot that emits a recognisable challenge page both breaks the deception and
 * signals "something is watching". This is a CI/test-only guard on no runtime path.
 */
final class WafLookalikeGuardTest extends TestCase
{
    private function guard(): WafLookalikeGuard
    {
        return WafLookalikeGuard::fromPackage();
    }

    /**
     * @dataProvider lookalikeBodies
     */
    public function test_scan_flags_every_challenge_tell(string $text): void
    {
        self::assertNotEmpty($this->guard()->scan($text));
    }

    /** @return array<string,array{0:string}> */
    public static function lookalikeBodies(): array
    {
        return [
            'branded waf footer' => ['<div>Protected by a Web Application Firewall</div>'],
            'bunkerweb footer' => ['<footer>secured by BunkerWeb</footer>'],
            'safeline' => ['blocked by SafeLine'],
            'sucuri block' => ['Access Denied - Sucuri Website Firewall'],
            'incapsula' => ['Incapsula incident ID: 1234-5678'],
            'cloudflare interstitial' => ['<title>Just a moment...</title>'],
            'cloudflare block' => ['Attention Required! | Cloudflare'],
            'cf markup' => ['<div class="cf-wrapper"><div class="cf-error-details">'],
            'ray id footer' => ['Ray ID: 7abc12def</span>'],
            'checking browser' => ['Checking your browser before accessing the site.'],
            'js+cookies' => ['Please enable JavaScript and cookies to continue'],
            'spinner class' => ['<div class="lds-roller"><div></div></div>'],
            'proof of work' => ['Please complete the proof of work to continue'],
            'pow loop shape' => ['while(true){ if(sha256(nonce).startsWith("0000")) break; }'],
            'challenge redirect' => ['<script>window.location = "/challenge?id=1"</script>'],
            'challenge location.replace' => ['<script>location.replace("/challenge")</script>'],
            'challenge meta refresh' => ['<meta http-equiv="refresh" content="0; url=/challenge?id=1">'],
            'challenge refresh header' => ['Refresh: 0; url=/challenge'],
        ];
    }

    /**
     * @dataProvider benignBodies
     */
    public function test_scan_passes_legitimate_honeypot_output(string $text): void
    {
        self::assertSame([], $this->guard()->scan($text));
    }

    /** @return array<string,array{0:string}> */
    public static function benignBodies(): array
    {
        // Plain 403 / Forbidden / Access Denied / spinners / redirects / bare `0000` are all
        // legitimate honeypot output and MUST NOT trip the gate — only the challenge-page SHAPE does.
        return [
            'plain 403' => ['<h1>403 Forbidden</h1><p>You don\'t have permission to access this resource.</p>'],
            'access denied prose' => ['Access Denied. Your account lacks the required role.'],
            'plain redirect' => ['<script>window.location = "/login"</script>'],
            'plain meta refresh' => ['<meta http-equiv="refresh" content="0; url=/dashboard">'],
            'hex color 0000' => ['body { background:#000000; color:#0000ff; }'],
            'digest with 0000' => ['sha256: 0000a1b2c3d4e5f6 (checksum)'],
            'generic spinner' => ['<div class="spinner loading"></div>'],
            'sql error' => ["You have an error in your SQL syntax near '' at line 1"],
            'challenge word in url only' => ['<a href="/api/v2/challenge/list">challenges</a>'],
        ];
    }

    public function test_every_pattern_compiles(): void
    {
        // A malformed regex makes @preg_match return false, which scan() treats as "no match" — a
        // silent efficacy hole. Assert every shipped pattern compiles so a bad edit fails HERE, not
        // silently in production CI.
        $tells = require dirname(__DIR__, 2) . '/resources/waf-lookalike-tells.php';
        foreach ((array) ($tells['patterns'] ?? []) as $pattern) {
            self::assertNotFalse(@preg_match('~' . $pattern . '~i', ''), "pattern must compile: {$pattern}");
        }
    }

    public function test_from_package_builds_a_non_empty_guard(): void
    {
        // fromPackage must fail CLOSED on a broken list, never build a no-op guard — so a real load
        // yields a guard that actually flags a known tell.
        self::assertNotEmpty($this->guard()->scan('secured by BunkerWeb'));
    }

    public function test_from_package_is_not_wired_into_any_runtime_denylist(): void
    {
        // Invariant: the WAF tells live in their OWN resource, separate from the runtime egress
        // denylist. If a tell ever leaked into the runtime denylist it would change the 404-decline
        // path — the one thing this ticket forbids.
        $runtime = require dirname(__DIR__, 2) . '/resources/fingerprint-denylist.php';
        $runtimeLiterals = (array) ($runtime['literals'] ?? []);
        foreach (['BunkerWeb', 'lds-roller', 'Web Application Firewall', 'Checking your browser'] as $tell) {
            self::assertNotContains($tell, $runtimeLiterals, "WAF tell {$tell} must NOT be in the runtime denylist");
        }
    }
}
