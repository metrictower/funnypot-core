<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0235 — crlfuzz canary-echo decoy (templates/attack/48-crlfuzz-crlf-echo.yaml).
 *
 * crlfuzz (dwisiswant0/crlfuzz) confirms a CRLF-injection vuln ONLY by finding a fixed marker
 * header `X-Injected-Header-By: CRLFuzz` in the response — isVuln() substring-checks the header
 * value; it never verifies the marker came from its own injected bytes. We recognise the two fixed
 * canary tokens (verified against pkg/crlfuzz/const.go: keyHeader="X-Injected-Header-By",
 * valHeader="CRLFuzz") in the request and emit that EXACT authored CONSTANT header — never a
 * reflection. This suite pins BOTH that crlfuzz confirms (KEY-1/3/4/5) AND that no attacker byte can
 * ever reach our response (KEY-2 — the inertness proof), plus no false confirmation (KEY-6).
 */
final class CrlfuzzEchoTest extends TestCase
{
    private function emulate(string $path, string $query = '', ?string $body = null, array $headers = []): ?object
    {
        return TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php')
            ->emulate(new RequestContext('GET', $path, $query, $headers, $body));
    }

    /**
     * KEY-1 — crlfuzz confirms: a canonical GenerateURL probe (escape="%0d%0a") yields the exact
     * confirming header, so crlfuzz's isVuln() (strings.Contains on the value) returns true.
     * Catches: the decoy staying silent, or the wrong rule matching.
     */
    public function test_key1_crlfuzz_probe_gets_the_confirming_header(): void
    {
        $r = $this->emulate('/%0d%0aX-Injected-Header-By%3a%20CRLFuzz');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame(['attack-crlfuzz-echo'], $r->satisfies->templateIds());
        self::assertArrayHasKey('X-Injected-Header-By', $r->headers);
        self::assertSame('CRLFuzz', $r->headers['X-Injected-Header-By']);
        // crlfuzz's confirm is a substring test — pin that the value literally contains the marker.
        self::assertStringContainsString('CRLFuzz', $r->headers['X-Injected-Header-By']);
    }

    /**
     * KEY-2 — THE INERTNESS PROOF. A probe that appends the crlfuzz canary AND an attacker-chosen
     * header + Set-Cookie. If this decoy were a real reflector it would decode the attacker CR/LF
     * block into our response header set (a genuine response-splitting / header-injection hole).
     * It provably cannot: the confirming header is an authored constant, `contains` conditions
     * produce no capture groups, and the render fast path returns the constant byte-identical.
     */
    public function test_key2_attacker_crlf_and_injected_header_are_not_reflected(): void
    {
        $r = $this->emulate('/%0d%0aX-Injected-Header-By%3a%20CRLFuzz%0d%0aX-Evil%3a%20pwned%0d%0aSet-Cookie%3a%20sid%3dattacker');
        self::assertNotNull($r);

        // The confirming header is present and EXACT — not `CRLFuzz\r\nX-Evil: pwned`.
        self::assertSame('CRLFuzz', $r->headers['X-Injected-Header-By']);

        // No attacker-chosen header entered the response header set.
        self::assertArrayNotHasKey('X-Evil', $r->headers);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);

        // No header name or value carries a raw CR/LF/NUL (no header splitting).
        foreach ($r->headers as $name => $value) {
            self::assertSame(0, preg_match('/[\r\n\x00]/', (string) $name), "header name split: {$name}");
            self::assertSame(0, preg_match('/[\r\n\x00]/', (string) $value), "header value split: {$name}");
        }

        // The attacker token appears in NO header name/value and NOT in the body.
        foreach ($r->headers as $name => $value) {
            self::assertStringNotContainsString('pwned', (string) $name);
            self::assertStringNotContainsString('pwned', (string) $value);
        }
        self::assertStringNotContainsString('pwned', $r->body);
        self::assertStringNotContainsString('attacker', $r->body);
    }

    /**
     * KEY-3 — the confirming header is a byte-identical CONSTANT regardless of the probe. Two
     * different escapes carrying different attacker payloads (incl. an injected Location:) must
     * yield the identical marker value and NEVER an attacker-influenced Location.
     * Catches: any path where the emitted value is assembled from / influenced by attacker bytes,
     * and an injected `Location:` (response-splitting → open redirect).
     */
    public function test_key3_confirming_header_is_a_constant_across_probes(): void
    {
        $a = $this->emulate('/%0d%0aX-Injected-Header-By%3a%20CRLFuzz%0d%0aX-Evil%3a%20pwned%0d%0aSet-Cookie%3a%20sid%3dattacker');
        $b = $this->emulate('/x?q=crlfuzz%0d%0aX-Injected-Header-By%3a%20CRLFuzz%0d%0aLocation%3a%20http%3a//evil');
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame('CRLFuzz', $a->headers['X-Injected-Header-By']);
        self::assertSame('CRLFuzz', $b->headers['X-Injected-Header-By']);
        self::assertSame($a->headers['X-Injected-Header-By'], $b->headers['X-Injected-Header-By']);
        self::assertArrayNotHasKey('Location', $a->headers);
        self::assertArrayNotHasKey('Location', $b->headers);
    }

    /**
     * KEY-4 — recognition covers non-CRLF escapes too. crlfuzz's escapeList includes entries with
     * no real CR/LF (e.g. "%20"), yet crlfuzz still sends them and still checks for the marker.
     * Recognition keys on the marker tokens, not on CR/LF presence.
     * Catches: a rule that mistakenly required a CR/LF sequence and so missed ~1/4 of crlfuzz probes.
     */
    public function test_key4_non_crlf_escape_still_confirms(): void
    {
        $r = $this->emulate('/%20X-Injected-Header-By%3a%20CRLFuzz');
        self::assertNotNull($r);
        self::assertSame('CRLFuzz', $r->headers['X-Injected-Header-By']);
        self::assertSame(['attack-crlfuzz-echo'], $r->satisfies->templateIds());
    }

    /**
     * KEY-5 — no-shadow / priority: crlfuzz wins over broad rules, including a `../`-bearing escape
     * (crlfuzz escapeList "%2f..%0d%0a", which decodes to `/..\r\n…`). It must not be grabbed by an
     * LFI/traversal rule first.
     */
    public function test_key5_crlfuzz_wins_over_traversal_escape(): void
    {
        $r = $this->emulate('/%2f..%0d%0aX-Injected-Header-By%3a%20CRLFuzz');
        self::assertNotNull($r);
        self::assertSame(['attack-crlfuzz-echo'], $r->satisfies->templateIds());
        self::assertSame('CRLFuzz', $r->headers['X-Injected-Header-By']);
    }

    /**
     * KEY-6 — benign negative: no false confirmation. Both canary tokens are required; ordinary
     * traffic carries neither, so no response may stamp the crlfuzz marker.
     */
    public function test_key6_benign_traffic_gets_no_marker(): void
    {
        $search = $this->emulate('/search', 'q=hello world');
        if ($search !== null) {
            self::assertArrayNotHasKey('X-Injected-Header-By', $search->headers);
        }

        $redirect = $this->emulate('/', 'redirect=//example.com');
        if ($redirect !== null) {
            self::assertNotSame(['attack-crlfuzz-echo'], $redirect->satisfies->templateIds());
            self::assertArrayNotHasKey('X-Injected-Header-By', $redirect->headers);
        }
    }
}
