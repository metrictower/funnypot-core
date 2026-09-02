<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoyTables;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The `decoy-session` behavior primitive: a stateless mock-auth mint/gate over a signed session
 * cookie. Pins the load-bearing security invariants with in-test FIXTURE rules (the flagship
 * phpMyAdmin templates are authored in a later task):
 *  - the signing key is a hard kill switch, checked before any Honeytoken/DecoySession exists;
 *  - mint never reflects a submitted value into Location (no open redirect);
 *  - gate fails closed on anything but a verified `s=1` cookie;
 *  - an authored base `response` (the login page) is what every decline falls back to.
 */
final class DecoySessionBehaviorTest extends TestCase
{
    private const KEY = 'S3cr3t-Decoy-Signing-Key-must-never-leak';

    private const LOGIN_STUB_MINT = '<html>LOGIN_STUB_MINT</html>';

    private const LOGIN_STUB_GATE = '<html>LOGIN_STUB_GATE</html>';

    /** @return array<string,mixed> */
    private function mintRule(): array
    {
        return [
            'id' => 'decoy-mint-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 200,
            'match' => [
                ['in' => 'method', 'regex' => '^POST$'],
                ['in' => 'path', 'regex' => '^/phpmyadmin/index\.php$'],
                [
                    'in' => 'body',
                    'regex' => 'user=(?P<user>[^&]*)&pass=(?P<pass>[^&]*)(?:&redirect=(?P<redirect>[^&]*))?',
                    'capture' => true,
                ],
            ],
            'response' => ['headers' => [], 'body' => self::LOGIN_STUB_MINT],
            'behavior' => 'decoy-session',
            'decoy-session' => [
                'mode' => 'mint',
                'cookie_name' => 'phpMyAdmin',
                'cookie_path' => '/phpmyadmin',
            ],
        ];
    }

    /** @return array<string,mixed> */
    private function gateRule(int $rows = 5): array
    {
        return [
            'id' => 'decoy-gate-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 200,
            'match' => [
                ['in' => 'method', 'regex' => '^GET$'],
                ['in' => 'path', 'regex' => '^/phpmyadmin/index\.php$'],
            ],
            'response' => ['headers' => [], 'body' => self::LOGIN_STUB_GATE],
            'behavior' => 'decoy-session',
            'decoy-session' => [
                'mode' => 'gate',
                'cookie_name' => 'phpMyAdmin',
                'cookie_path' => '/phpmyadmin',
                'domain' => 'example.test',
                'table_key' => 'users',
                'rows' => $rows,
            ],
        ];
    }

    /** @return array<string,mixed> a gate rule naming a behavior this build never registers */
    private function bogusBehaviorGateRule(): array
    {
        $rule = $this->gateRule();
        $rule['id'] = 'decoy-gate-bogus-behavior-fixture';
        $rule['match'][1]['regex'] = '^/phpmyadmin/other\.php$';
        $rule['behavior'] = 'decoy-session-not-registered';

        return $rule;
    }

    private function emulator(array $rules, ?string $key = self::KEY): TemplateAttackEmulator
    {
        return new TemplateAttackEmulator($rules, [], null, null, [], null, $key);
    }

    private function mintBody(string $user, string $pass, ?string $redirect = null): string
    {
        $body = 'user=' . $user . '&pass=' . $pass;
        if ($redirect !== null) {
            $body .= '&redirect=' . $redirect;
        }

        return $body;
    }

    /** The name=value pair a browser would send back, parsed out of a full Set-Cookie string. */
    private function cookieHeaderFrom(string $setCookie): string
    {
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    // --- mint: success --------------------------------------------------------------------

    public function test_mint_valid_creds_returns_302_with_signed_s1_cookie(): void
    {
        $em = $this->emulator([$this->mintRule()]);
        $r = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody('alice', 'hunter2')));

        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertSame('/phpmyadmin/index.php', $r->headers['Location']);
        self::assertArrayHasKey('Set-Cookie', $r->headers);
        self::assertStringContainsString('path=/phpmyadmin; HttpOnly', $r->headers['Set-Cookie']);

        // The token verifies and decodes to s=1 (mirrors DecoySession's own contract).
        $nameValue = $this->cookieHeaderFrom($r->headers['Set-Cookie']);
        $eq = strpos($nameValue, '=');
        self::assertNotFalse($eq);
        self::assertSame('phpMyAdmin', substr($nameValue, 0, $eq));
        $rawValue = substr($nameValue, $eq + 1);
        $payload = (new Honeytoken(self::KEY))->verifiedPayload($rawValue);
        self::assertSame('s=1', $payload);

        // Key discipline: the signing key itself never appears in any emitted header/body.
        self::assertStringNotContainsString(self::KEY, $r->headers['Set-Cookie']);
        self::assertStringNotContainsString(self::KEY, $r->headers['Location']);
        self::assertStringNotContainsString(self::KEY, $r->body);
    }

    public function test_mint_never_reflects_a_crafted_redirect_field_open_redirect(): void
    {
        // A crafted pma_servername/redirect-style field must have zero effect: Location is a
        // fixed literal, never woven from any submitted value.
        $em = $this->emulator([$this->mintRule()]);
        $r = $em->emulate(new RequestContext(
            'POST',
            '/phpmyadmin/index.php',
            '',
            [],
            $this->mintBody('alice', 'hunter2', 'http%3A%2F%2Fevil.example%2Fpwn')
        ));

        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertSame('/phpmyadmin/index.php', $r->headers['Location'], 'Location must be the fixed literal, never the submitted redirect');
        self::assertStringNotContainsString('evil.example', $r->headers['Location']);
    }

    // --- mint: reject empty/whitespace/implausible creds -----------------------------------

    public function test_mint_empty_username_falls_back_to_login_page(): void
    {
        $em = $this->emulator([$this->mintRule()]);
        $r = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody('', 'hunter2')));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_MINT, $r->body);
        self::assertNotSame(302, $r->status);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
    }

    public function test_mint_empty_password_falls_back_to_login_page(): void
    {
        $em = $this->emulator([$this->mintRule()]);
        $r = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody('alice', '')));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_MINT, $r->body);
        self::assertNotSame(302, $r->status);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
    }

    public function test_mint_whitespace_only_creds_fall_back_to_login_page(): void
    {
        $em = $this->emulator([$this->mintRule()]);
        // A literal space (not '+' — that isn't whitespace until URL-decoded, and the handler
        // never decodes) is a whitespace-only username: trim() reduces it to ''.
        $r = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody(' ', 'hunter2')));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_MINT, $r->body, 'a whitespace-only username is not a login attempt');
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
    }

    public function test_mint_implausible_username_falls_back_to_login_page(): void
    {
        $em = $this->emulator([$this->mintRule()]);
        $r = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody('<script>', 'hunter2')));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_MINT, $r->body);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
    }

    // --- gate: success/decline --------------------------------------------------------------

    public function test_gate_valid_s1_cookie_returns_the_authed_dashboard(): void
    {
        $mintEm = $this->emulator([$this->mintRule()]);
        $mint = $mintEm->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody('alice', 'hunter2')));
        self::assertNotNull($mint);
        $cookieHeader = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);

        $gateEm = $this->emulator([$this->gateRule()]);
        $r = $gateEm->emulate(new RequestContext('GET', '/phpmyadmin/index.php', '', ['Cookie' => $cookieHeader]));

        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        // Phase B: the authed body is the shared core PhpMyAdminSkin — the phpMyAdmin topbar, the full
        // table tree, and the selected table's results grid. Assert on stable content, not the
        // seed-derived class prefix.
        self::assertStringContainsString('phpMyAdmin', $r->body);
        self::assertStringContainsString('<table', $r->body);
        // FP-0282: the tree lists THIS deploy's seeded table story. This emulator is unwired
        // (personaSeed null), so emulate()'s default seed 0 is the identity seed — derive the expected
        // names from the helper at seed 0 rather than re-pinning the old six-name fleet constant.
        foreach (DecoyTables::names(0) as $t) {
            self::assertStringContainsString('>' . $t . '</li>', $r->body, $t . ' must appear in the table tree');
        }
        self::assertStringNotContainsString(self::LOGIN_STUB_GATE, $r->body);
        self::assertStringNotContainsString(self::KEY, $r->body);
    }

    public function test_gate_valid_s0_cookie_is_not_authenticated(): void
    {
        // A validly-signed s=0 (pre-auth marker) must NOT authenticate — different payload class,
        // not a weaker s=1.
        $mintEm = $this->emulator([$this->mintRule()]);
        // Build an s=0 cookie the same way DecoySession would, without relying on a mint success.
        $s0 = (new Honeytoken(self::KEY))->cookie('phpMyAdmin', 's=0', '/phpmyadmin');
        $cookieHeader = $this->cookieHeaderFrom($s0);

        $gateEm = $this->emulator([$this->gateRule()]);
        $r = $gateEm->emulate(new RequestContext('GET', '/phpmyadmin/index.php', '', ['Cookie' => $cookieHeader]));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_GATE, $r->body);
        self::assertStringNotContainsString('phpMyAdmin', $r->body, 's=0 must never render the authed dashboard');
    }

    public function test_gate_garbage_cookie_falls_back_to_login_page(): void
    {
        $gateEm = $this->emulator([$this->gateRule()]);
        $r = $gateEm->emulate(new RequestContext('GET', '/phpmyadmin/index.php', '', ['Cookie' => 'phpMyAdmin=garbage-not-signed']));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_GATE, $r->body);
    }

    public function test_gate_absent_cookie_falls_back_to_login_page(): void
    {
        $gateEm = $this->emulator([$this->gateRule()]);
        $r = $gateEm->emulate(new RequestContext('GET', '/phpmyadmin/index.php'));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_GATE, $r->body);
    }

    public function test_gate_null_request_falls_back_to_login_page(): void
    {
        // The position-blind port path: no request at all, mirroring handleIterate's degrade.
        $gateEm = $this->emulator([$this->gateRule()]);
        $r = $gateEm->renderRule($this->gateRule(), [], 0, null);

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_GATE, $r->body);
    }

    public function test_gate_reads_a_lowercase_cookie_header_case_insensitively(): void
    {
        $mintEm = $this->emulator([$this->mintRule()]);
        $mint = $mintEm->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody('alice', 'hunter2')));
        self::assertNotNull($mint);
        $cookieHeader = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);

        $gateEm = $this->emulator([$this->gateRule()]);
        $r = $gateEm->emulate(new RequestContext('GET', '/phpmyadmin/index.php', '', ['cookie' => $cookieHeader]));

        self::assertNotNull($r);
        self::assertStringContainsString('phpMyAdmin', $r->body);
    }

    // --- key discipline: null/empty key is a hard kill switch ------------------------------

    public function test_disabled_key_null_declines_mint_to_the_login_page(): void
    {
        $em = $this->emulator([$this->mintRule()], null);
        $r = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody('alice', 'hunter2')));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_MINT, $r->body);
        self::assertNotSame(302, $r->status);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
    }

    public function test_disabled_key_empty_string_declines_gate_to_the_login_page(): void
    {
        $em = $this->emulator([$this->gateRule()], '');
        // Even a request with NO cookie at all still just falls to the base — feature is off,
        // no Honeytoken/DecoySession is ever constructed, so this can't error either.
        $r = $em->emulate(new RequestContext('GET', '/phpmyadmin/index.php'));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_GATE, $r->body);
    }

    // --- base fail-closed: an unregistered behavior serves the authored base (R2-6) --------

    public function test_unregistered_behavior_name_serves_the_login_page_base(): void
    {
        $rule = $this->bogusBehaviorGateRule();
        $em = $this->emulator([$rule]);
        $r = $em->emulate(new RequestContext('GET', '/phpmyadmin/other.php'));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_GATE, $r->body);
        self::assertStringNotContainsString('phpMyAdmin', $r->body, 'an unregistered behavior must never leak the authed dashboard');
    }

    // --- throw-free on malformed input -------------------------------------------------------

    public function test_malformed_cookies_never_throw(): void
    {
        $gateEm = $this->emulator([$this->gateRule()]);

        foreach (['no-equals-sign-anywhere', '', 'phpMyAdmin=', 'phpMyAdmin=nodothere', ';;;'] as $cookie) {
            $r = $gateEm->emulate(new RequestContext('GET', '/phpmyadmin/index.php', '', ['Cookie' => $cookie]));
            self::assertNotNull($r, $cookie);
            self::assertSame(self::LOGIN_STUB_GATE, $r->body, $cookie);
        }
    }

    public function test_null_body_mint_post_never_throws(): void
    {
        $em = $this->emulator([$this->mintRule()]);
        // No body at all -> the rule's own match fails (no user/pass to capture), so this exercises
        // the whole path end to end with a null body and must simply decline, never throw.
        $r = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], null));

        self::assertNull($r);
    }

    // --- canonical trailing-slash 301 (DirectorySlash) -------------------------------------

    /** @return array<string,mixed> a gate rule matching the panel roots, with canonical-slash 301 on. */
    private function canonicalGateRule(): array
    {
        return [
            'id' => 'decoy-gate-canonical-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 200,
            'match' => [
                ['in' => 'method', 'regex' => '^(?:GET|HEAD)$'],
                ['in' => 'path', 'regex' => '^/(?:phpmyadmin|pma)(?:/index\.php)?/*$', 'ci' => true],
            ],
            'response' => ['headers' => [], 'body' => self::LOGIN_STUB_GATE],
            'behavior' => 'decoy-session',
            'decoy-session' => [
                'mode' => 'gate',
                'cookie_name' => 'phpMyAdmin',
                'cookie_path' => '/phpmyadmin',
                'domain' => 'example.test',
                'table_key' => 'users',
                'rows' => 3,
                'canonical_slash' => true,
            ],
        ];
    }

    public function test_gate_canonical_slash_301s_a_bare_directory_to_the_trailing_slash(): void
    {
        $em = $this->emulator([$this->canonicalGateRule()]);

        $bare = $em->emulate(new RequestContext('GET', '/phpmyadmin'));
        self::assertNotNull($bare);
        self::assertSame(301, $bare->status, 'a bare /phpmyadmin must 301 to the trailing-slash form');
        self::assertSame('/phpmyadmin/', $bare->headers['Location']);

        $pma = $em->emulate(new RequestContext('GET', '/pma'));
        self::assertNotNull($pma);
        self::assertSame(301, $pma->status);
        self::assertSame('/pma/', $pma->headers['Location']);
    }

    public function test_gate_canonical_slash_leaves_slashed_and_file_paths_alone(): void
    {
        $em = $this->emulator([$this->canonicalGateRule()]);

        // Already slashed -> serve the login page, no redirect.
        $slashed = $em->emulate(new RequestContext('GET', '/phpmyadmin/'));
        self::assertNotNull($slashed);
        self::assertSame(self::LOGIN_STUB_GATE, $slashed->body);
        self::assertNotSame(301, $slashed->status);

        // A file path (…/index.php) -> serve the login page, no redirect.
        $file = $em->emulate(new RequestContext('GET', '/phpmyadmin/index.php'));
        self::assertNotNull($file);
        self::assertSame(self::LOGIN_STUB_GATE, $file->body);
        self::assertNotSame(301, $file->status);
    }

    public function test_gate_without_canonical_slash_serves_login_on_a_bare_directory(): void
    {
        // The opt-in is off by default: the standard gateRule() (no canonical_slash) must still serve
        // the login page for a bare directory, never a 301.
        $rule = $this->gateRule();
        $rule['match'][1]['regex'] = '^/(?:phpmyadmin|pma)(?:/index\.php)?/*$';
        $rule['match'][1]['ci'] = true;
        $em = $this->emulator([$rule]);

        $r = $em->emulate(new RequestContext('GET', '/phpmyadmin'));
        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB_GATE, $r->body);
        self::assertNotSame(301, $r->status);
    }

    // --- row cap --------------------------------------------------------------------------

    public function test_gate_row_count_is_capped_at_the_code_ceiling(): void
    {
        $mintEm = $this->emulator([$this->mintRule()]);
        $mint = $mintEm->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], $this->mintBody('alice', 'hunter2')));
        self::assertNotNull($mint);
        $cookieHeader = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);

        // Authored 500 rows, far past MAX_DECOY_ROWS (100) — the code constant re-clamps it.
        $gateEm = $this->emulator([$this->gateRule(500)]);
        $r = $gateEm->emulate(new RequestContext('GET', '/phpmyadmin/index.php', '', ['Cookie' => $cookieHeader]));

        self::assertNotNull($r);
        // Count only <tbody> data rows — the skin's results grid also emits one <thead> header <tr>.
        $tbody = strstr($r->body, '<tbody>');
        self::assertIsString($tbody, 'the results grid must render a tbody');
        self::assertSame(100, substr_count($tbody, '<tr>'), 'data rows must be hard-capped at MAX_DECOY_ROWS (100)');
    }
}
