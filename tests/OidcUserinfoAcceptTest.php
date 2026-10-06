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
 * FP-0379 — the OIDC userinfo accept-loop (/auth/userinfo). A JWT-shaped bearer is accepted with NO
 * validation (forged alg:none / wrong-key / tampered all pass) → a 200 "almost-admin" userinfo body with
 * next-route hints; a bearer-less request → the inert 401 problem+json baseline. The two-claimant arrangement
 * means the advertised endpoint resolves whether attack emulation is on (200-upgrade) or off (401 baseline).
 * Inert by construction: no session, no secret, no reflected attacker bytes.
 */
final class OidcUserinfoAcceptTest extends TestCase
{
    /** @var array<string,mixed> */
    private static function index(): array
    {
        return require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    }

    private function engine(bool $attackEmulation): Honeypot
    {
        $cfg = new Config(
            'respond',
            static fn (RequestContext $r): bool => true,
            'matched-only',
            static fn (RequestContext $r): string => 'fixed',
            'coherent',
            Style::REALISTIC,
            'high',
            65536, 0, 0, false, null, null, null, 'fixed'
        );
        $cfg->attackEmulation = $attackEmulation;

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    /** @param array<string,string> $headers */
    private function get(string $path, array $headers = [], bool $attackEmulation = true): ?object
    {
        return $this->engine($attackEmulation)->respond(new RequestContext('GET', $path, '', $headers, null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    /** A JWT-shaped bearer header (header value only — the gate never parses or validates it). */
    private function bearer(string $token): array
    {
        return ['Authorization' => 'Bearer ' . $token];
    }

    public function test_forged_alg_none_bearer_is_accepted_into_almost_admin(): void
    {
        // alg:none forgery: {"alg":"none"}.{"sub":"admin","role":"superuser"}. (unsigned — a real OIDC
        // provider rejects it; the decoy ACCEPTS it, which is the deception.)
        $r = $this->get('/auth/userinfo', $this->bearer('eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.'));
        self::assertSame(200, $r->status ?? null);
        self::assertSame('application/json', $r->headers['Content-Type'] ?? null);
        $b = $this->body($r);
        self::assertNotNull(json_decode($b), 'the almost-admin body is valid JSON');
        self::assertStringContainsString('billing-admin', $b, 'near-admin role tease');
        self::assertStringContainsString('reports:read', $b, 'near-admin scope tease');
    }

    public function test_tampered_and_wrong_key_bearers_all_get_the_same_200(): void
    {
        // Three different forgeries (tampered payload, wrong-key signature, garbage) must ALL be accepted
        // identically — proof there is no signature/secret validation.
        $tokens = [
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9.dGFtcGVyZWQ',
            'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.wrongkeysignatureAAAAAAAAAAAAAAAAAAAAAAAA',
            'aaaa.bbbb.cccc',
        ];
        $first = null;
        foreach ($tokens as $t) {
            $r = $this->get('/auth/userinfo', $this->bearer($t));
            self::assertSame(200, $r->status ?? null, "forged token must be accepted: {$t}");
            $first ??= $this->body($r);
            self::assertSame($first, $this->body($r), 'every forgery yields the identical seeded body (no validation, no reflection)');
        }
    }

    public function test_almost_admin_teases_but_never_grants_super_admin(): void
    {
        // The whole point of the loop: near-admin, never actually admin — so claim permutation keeps finding
        // "slightly more" instead of either a 401 wall or a real grant.
        $b = $this->body($this->get('/auth/userinfo', $this->bearer('a.b.c')));
        self::assertStringNotContainsString('super_admin', $b);
        self::assertStringNotContainsString('admin:', $b, 'no admin:* scope is ever granted');
    }

    public function test_no_bearer_is_the_401_dead_end_with_attack_emulation_on(): void
    {
        $r = $this->get('/auth/userinfo', [], true);
        self::assertSame(401, $r->status ?? null);
        self::assertSame('application/problem+json', $r->headers['Content-Type'] ?? null);
        self::assertStringContainsString('"title": "Unauthorized"', $this->body($r));
    }

    public function test_no_bearer_is_the_401_baseline_with_attack_emulation_off(): void
    {
        // C1: with attack emulation OFF the owns_path upgrade is not built, so the route-tier 405 new_page
        // baseline must still serve the advertised endpoint a coherent 401 (no partial-tree tell).
        $r = $this->get('/auth/userinfo', [], false);
        self::assertSame(401, $r->status ?? null);
        self::assertSame('application/problem+json', $r->headers['Content-Type'] ?? null);
        self::assertStringContainsString('"title": "Unauthorized"', $this->body($r));
    }

    public function test_non_bearer_authorization_is_not_accepted(): void
    {
        // A Basic auth header is not a JWT bearer, so the gate misses and the request falls to the 401.
        $r = $this->get('/auth/userinfo', ['Authorization' => 'Basic dXNlcjpwYXNz']);
        self::assertSame(401, $r->status ?? null);
    }

    public function test_bearer_scheme_is_case_insensitive(): void
    {
        $r = $this->get('/auth/userinfo', ['Authorization' => 'bearer a.b.c']);
        self::assertSame(200, $r->status ?? null, 'lower-case scheme still accepted (ci gate)');
    }

    public function test_trailing_slash_variant_is_owned_and_served(): void
    {
        $r = $this->get('/auth/userinfo/', $this->bearer('a.b.c'));
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('billing-admin', $this->body($r));
    }

    public function test_200_body_reflects_no_attacker_bytes(): void
    {
        // A token carrying JSON-breaking / injected bytes must never surface in the body — the gate is a pure
        // boolean (no capture), so the seeded body is byte-identical regardless of the token.
        $marker = 'ZZINJECTED";}{"x":"';
        $r = $this->get('/auth/userinfo', $this->bearer('a.b.' . $marker));
        $b = $this->body($r);
        self::assertStringNotContainsString('ZZINJECTED', $b, 'no attacker byte is reflected');
        self::assertNotNull(json_decode($b), 'body stays valid JSON');
    }

    public function test_links_hints_resolve_to_served_decoys(): void
    {
        // The _links "lead deeper" to real owned decoys — a dangling hint would silently rebuild the 404 wall
        // this ticket removes (scanBody does not lint JSON _links, so assert it here). Resolve each against the
        // attackEmulation-OFF engine (route-tier decoys serve regardless of emulation).
        $decoded = json_decode($this->body($this->get('/auth/userinfo', $this->bearer('a.b.c'))), true);
        self::assertIsArray($decoded['_links'] ?? null, 'the almost-admin body carries _links');

        $off = $this->engine(false);
        foreach ($decoded['_links'] as $rel => $url) {
            if ($rel === 'self') {
                continue; // self points back at /auth/userinfo, already proven above
            }
            $path = (string) parse_url((string) $url, PHP_URL_PATH);
            $resp = $off->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
            self::assertNotNull($resp, "hinted route {$rel} ({$path}) must resolve to a served decoy, not a 404");
            self::assertContains($resp->status, [200, 401], "hinted route {$path} must be an inert 200/401");
        }
    }

    public function test_memos_style_other_auth_paths_stay_untouched(): void
    {
        // The dedicated /auth/userinfo must not disturb the sibling /auth decoys (401).
        foreach (['/auth', '/auth/login', '/auth/token'] as $p) {
            $r = $this->get($p, [], false);
            self::assertSame(401, $r->status ?? null, "{$p} stays the inert 401 baseline");
        }
    }
}
