<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use RuntimeException;
use PHPUnit\Framework\TestCase;

/**
 * FP-0271 — compiler validation for the two new decoy-session keys: the mint `redirect` (a static
 * rooted-relative literal, no-open-redirect by construction) and the gate `panel` (a closed enum).
 * These are the build-time falsifiers behind the runtime no-open-redirect / closed-panel invariants.
 */
final class DecoySessionPanelRedirectCompilerTest extends TestCase
{
    /** @return array<int,array<string,mixed>> */
    private function compileOne(string $yaml): array
    {
        $dir = sys_get_temp_dir() . '/funnypot-decoy-' . getmypid() . '-' . uniqid();
        if (!mkdir($dir, 0775, true) && !is_dir($dir)) {
            self::fail("cannot create temp corpus dir {$dir}");
        }
        file_put_contents($dir . '/rule.yaml', $yaml);
        try {
            return (new EmulatorCompiler())->compile($dir);
        } finally {
            @unlink($dir . '/rule.yaml');
            @rmdir($dir);
        }
    }

    private function mintRule(string $redirectLine): string
    {
        return <<<YAML
id: decoy-mint-fixture
priority: 39
owns_path: [/wp-login.php]
match:
  - in: path
    regex: '(?:^|/)wp-login\\.php/*\$'
    ci: true
  - in: method
    regex: '^POST\$'
response:
  body: base-login-page
behavior: decoy-session
decoy-session:
  mode: mint
  cookie_name: sess
  cookie_path: /
{$redirectLine}
YAML;
    }

    private function gateRule(string $panelLine, string $cookieName = 'sess'): string
    {
        return <<<YAML
id: decoy-gate-fixture
priority: 104
owns_path: [/wp-admin, /wp-admin/]
match:
  - in: path
    regex: '^/wp-admin/*\$'
    ci: true
  - in: method
    regex: '^(?:GET|HEAD)\$'
    ci: true
status: 302
response:
  headers:
    Location: /wp-login.php
  body: ""
behavior: decoy-session
decoy-session:
  mode: gate
  cookie_name: {$cookieName}
  cookie_path: /
{$panelLine}
YAML;
    }

    // --- redirect (mint) ---------------------------------------------------------------------

    public function test_mint_redirect_defaults_to_the_phpmyadmin_panel_when_absent(): void
    {
        $rules = $this->compileOne($this->mintRule(''));
        self::assertSame('/phpmyadmin/index.php', $rules[0]['decoy-session']['redirect']);
    }

    public function test_mint_redirect_accepts_a_rooted_relative_literal(): void
    {
        $rules = $this->compileOne($this->mintRule('  redirect: /wp-admin/'));
        self::assertSame('/wp-admin/', $rules[0]['decoy-session']['redirect']);
    }

    /** @dataProvider badRedirects */
    public function test_mint_redirect_rejects_absolute_protocol_relative_and_crlf_targets(string $bad): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->mintRule('  redirect: ' . $bad));
    }

    /** @return array<string,array{0:string}> */
    public function badRedirects(): array
    {
        return [
            'absolute http'     => ["'https://evil.example/'"],
            'protocol relative' => ["'//evil.example/'"],
            'no leading slash'  => ["'wp-admin/'"],
            'backslash'         => ["'/wp-admin\\\\x'"],
            'directive'         => ["'/{{persona.company.domain}}/'"],
            'empty'             => ["''"],
        ];
    }

    // --- panel (gate) ------------------------------------------------------------------------

    public function test_gate_panel_defaults_to_phpmyadmin_when_absent(): void
    {
        $rules = $this->compileOne($this->gateRule(''));
        self::assertSame('phpmyadmin', $rules[0]['decoy-session']['panel']);
    }

    public function test_gate_panel_accepts_the_wordpress_value(): void
    {
        $rules = $this->compileOne($this->gateRule('  panel: wordpress'));
        self::assertSame('wordpress', $rules[0]['decoy-session']['panel']);
    }

    public function test_gate_panel_rejects_unknown_value(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->gateRule('  panel: grafana'));
    }

    // --- cookie_name directive lint ----------------------------------------------------------

    public function test_cookie_name_accepts_a_known_persona_directive(): void
    {
        $rules = $this->compileOne($this->gateRule('', "'wordpress_logged_in_{{persona.wordpress.cookieHash}}'"));
        self::assertStringContainsString('{{persona.wordpress.cookieHash}}', (string) $rules[0]['decoy-session']['cookie_name']);
    }

    public function test_cookie_name_rejects_an_unknown_directive(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->gateRule('', "'x_{{persona.wordpress.bogus}}'"));
    }

    // --- FP-0492: two_factor (mint) + challenge mode -----------------------------------------

    private function mintRuleLines(string $lines): string
    {
        return <<<YAML
id: decoy-mint-2fa-fixture
priority: 39
owns_path: [/wp-login.php]
match:
  - in: path
    regex: '(?:^|/)wp-login\\.php/*\$'
    ci: true
  - in: method
    regex: '^POST\$'
response:
  body: base-login-page
behavior: decoy-session
decoy-session:
  mode: mint
  cookie_name: sess
  cookie_path: /
  redirect: /wp-admin/
{$lines}
YAML;
    }

    private function challengeRule(string $lines): string
    {
        return <<<YAML
id: decoy-challenge-fixture
priority: 35
match:
  - in: path
    regex: '(?:^|/)wp-login\\.php/*\$'
    ci: true
  - in: method
    regex: '^(?:GET|HEAD)\$'
    ci: true
  - in: query
    regex: '(?:^|&)action=2fa(?:&|\$)'
    ci: true
response:
  body: base-login-page
behavior: decoy-session
decoy-session:
  mode: challenge
  cookie_name: sess
  cookie_path: /
{$lines}
YAML;
    }

    public function test_mint_two_factor_defaults_to_false(): void
    {
        $rules = $this->compileOne($this->mintRuleLines(''));
        self::assertFalse($rules[0]['decoy-session']['two_factor']);
        self::assertArrayNotHasKey('two_factor_redirect', $rules[0]['decoy-session']);
    }

    public function test_mint_two_factor_on_requires_a_two_factor_redirect(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->mintRuleLines('  two_factor: true'));
    }

    public function test_mint_two_factor_on_stores_the_challenge_redirect(): void
    {
        $rules = $this->compileOne($this->mintRuleLines("  two_factor: true\n  two_factor_redirect: /wp-login.php?action=2fa"));
        self::assertTrue($rules[0]['decoy-session']['two_factor']);
        self::assertSame('/wp-login.php?action=2fa', $rules[0]['decoy-session']['two_factor_redirect']);
    }

    public function test_mint_two_factor_redirect_rejects_an_absolute_target(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->mintRuleLines("  two_factor: true\n  two_factor_redirect: 'https://evil.example/'"));
    }

    public function test_challenge_form_action_defaults_when_absent(): void
    {
        $rules = $this->compileOne($this->challengeRule('  panel: wordpress'));
        self::assertSame('challenge', $rules[0]['decoy-session']['mode']);
        self::assertSame('/wp-login.php?action=2fa', $rules[0]['decoy-session']['form_action']);
        self::assertSame('wordpress', $rules[0]['decoy-session']['panel']);
    }

    public function test_challenge_form_action_accepts_a_rooted_relative_literal(): void
    {
        $rules = $this->compileOne($this->challengeRule('  form_action: /wp-login.php?action=2fa'));
        self::assertSame('/wp-login.php?action=2fa', $rules[0]['decoy-session']['form_action']);
    }

    public function test_challenge_form_action_rejects_an_absolute_target(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->challengeRule("  form_action: 'https://evil.example/'"));
    }

    public function test_challenge_panel_rejects_unknown_value(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->challengeRule('  panel: grafana'));
    }

    // --- credential_bypass (mint, FP-0561) ---------------------------------------------------

    public function test_mint_credential_bypass_absent_by_default(): void
    {
        $rules = $this->compileOne($this->mintRule(''));
        self::assertArrayNotHasKey('credential_bypass', $rules[0]['decoy-session'], 'absent ⇒ scalar gate only (unchanged)');
    }

    public function test_mint_accepts_credential_bypass_nosql_operator(): void
    {
        $rules = $this->compileOne($this->mintRule('  credential_bypass: nosql-operator'));
        self::assertSame('nosql-operator', $rules[0]['decoy-session']['credential_bypass']);
    }

    public function test_mint_rejects_unknown_credential_bypass(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->mintRule('  credential_bypass: anything-else'));
    }

    // --- FP-0007: cookie_same_site (all modes), credential_encoding (mint), basic mode ------------

    private function basicRule(string $extraLines): string
    {
        return <<<YAML
id: decoy-basic-fixture
priority: 69
owns_path: [/manager/html]
match:
  - in: path
    regex: '^/manager/html/*\$'
    ci: true
  - in: method
    regex: '^(?:GET|HEAD)\$'
    ci: true
status: 401
response:
  headers:
    WWW-Authenticate: Basic realm="Tomcat Manager Application"
  body: auth-required
behavior: decoy-session
decoy-session:
  mode: basic
  cookie_name: JSESSIONID
  cookie_path: /manager
{$extraLines}
YAML;
    }

    public function test_same_site_defaults_to_omit_empty_token(): void
    {
        $rules = $this->compileOne($this->mintRule(''));
        self::assertSame('', $rules[0]['decoy-session']['cookie_same_site'], 'absent ⇒ omit ⇒ historical tail');
    }

    public function test_same_site_lax_and_strict_pass_through(): void
    {
        $lax = $this->compileOne($this->mintRule('  cookie_same_site: lax'));
        self::assertSame('lax', $lax[0]['decoy-session']['cookie_same_site']);
        $strict = $this->compileOne($this->mintRule('  cookie_same_site: strict'));
        self::assertSame('strict', $strict[0]['decoy-session']['cookie_same_site']);
    }

    public function test_same_site_rejects_unknown_value(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->mintRule('  cookie_same_site: none'));
    }

    public function test_mint_credential_encoding_defaults_to_raw(): void
    {
        $rules = $this->compileOne($this->mintRule(''));
        self::assertSame('raw', $rules[0]['decoy-session']['credential_encoding']);
    }

    public function test_mint_credential_encoding_accepts_form(): void
    {
        $rules = $this->compileOne($this->mintRule('  credential_encoding: form'));
        self::assertSame('form', $rules[0]['decoy-session']['credential_encoding']);
    }

    public function test_mint_credential_encoding_rejects_unknown(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->mintRule('  credential_encoding: base64'));
    }

    public function test_basic_mode_compiles_with_a_panel(): void
    {
        $rules = $this->compileOne($this->basicRule('  panel: tomcat'));
        self::assertSame('basic', $rules[0]['decoy-session']['mode']);
        self::assertSame('tomcat', $rules[0]['decoy-session']['panel']);
    }

    public function test_basic_mode_accepts_pgadmin_panel(): void
    {
        $rules = $this->compileOne($this->basicRule('  panel: pgadmin'));
        self::assertSame('pgadmin', $rules[0]['decoy-session']['panel']);
    }

    public function test_basic_mode_requires_a_panel(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->basicRule(''));
    }

    public function test_basic_mode_rejects_unknown_panel(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->basicRule('  panel: grafana'));
    }

    /** @dataProvider forbiddenBasicKeys */
    public function test_basic_mode_rejects_wrong_mode_keys(string $line): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne($this->basicRule("  panel: tomcat\n{$line}"));
    }

    /** @return array<string,array{0:string}> */
    public function forbiddenBasicKeys(): array
    {
        return [
            'redirect'            => ['  redirect: /manager/html'],
            'credential_encoding' => ['  credential_encoding: form'],
            'domain'              => ['  domain: example.test'],
            'table_key'           => ['  table_key: users'],
            'rows'                => ['  rows: 5'],
            'canonical_slash'     => ['  canonical_slash: true'],
            'two_factor'          => ['  two_factor: true'],
            'form_action'         => ['  form_action: /manager/html'],
        ];
    }
}
