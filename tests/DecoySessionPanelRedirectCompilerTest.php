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
}
