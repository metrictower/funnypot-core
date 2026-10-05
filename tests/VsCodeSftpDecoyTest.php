<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * FP-0423 (Part 1): VSCode SFTP credential exposure decoy. The corpus routes /.vscode/sftp.json,
 * /sftp.json and /.config/sftp.json to the `vscode-sftp` bundle, previously answered by a degenerate
 * invalid-JSON stub (name/protocol/host, no credentials). This enrich dresses all three with a valid
 * VS Code sftp.json carrying a SEEDED, deploy-stable canary credential (persona.db.user/password),
 * coherent with the same creds leaked in /.env + /secrets.json. A worm (INtrack vscode_sftp_worm.py)
 * extracts the creds with a naive `{[^}]+}` regex and pivots. Parts 2+3 (registry + cross-protocol
 * correlation) are app-tier (FP-0562). Fixture: full compiled corpus via Honeypot::respond().
 */
final class VsCodeSftpDecoyTest extends TestCase
{
    private const PATHS = ['/.vscode/sftp.json', '/sftp.json', '/.config/sftp.json'];

    /** @var array<string,mixed>|null */
    private static $idx;

    /** @var array<string,Honeypot> per-seed engine cache — caps Honeypot churn across the seed sweep. */
    private static $engines = [];

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (isset(self::$engines[$seed])) {
            return self::$engines[$seed];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'high',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return self::$engines[$seed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function resp(string $path, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_serves_valid_json_on_all_paths(): void
    {
        foreach (self::PATHS as $p) {
            $r = $this->resp($p);
            self::assertSame(200, $r->status ?? null, "{$p} must serve 200");
            self::assertStringContainsString('application/json', (string) ($r->headers['Content-Type'] ?? ''), "{$p} CT");
            self::assertNotNull(json_decode($this->body($r)), "{$p} must be valid JSON: {$this->body($r)}");
        }
    }

    public function test_worm_bodywords_present(): void
    {
        foreach (self::PATHS as $p) {
            $b = $this->body($this->resp($p));
            foreach (['"name":', '"host":', '"protocol":', '"username":', '"password":'] as $w) {
                self::assertStringContainsString($w, $b, "{$p} must carry {$w}");
            }
        }
    }

    public function test_naive_regex_extraction_yields_credentials(): void
    {
        // INtrack's extractor is a naive {[^}]+} first-brace span — the inline_field taunt must not truncate it.
        foreach (self::PATHS as $p) {
            $b = $this->body($this->resp($p));
            self::assertSame(1, preg_match('/\{[^}]+\}/s', $b, $m), "{$p} naive brace span must match");
            $parsed = json_decode($m[0], true);
            self::assertIsArray($parsed, "{$p} naive span must parse");
            self::assertNotEmpty($parsed['username'] ?? '', "{$p} must yield a username");
            self::assertNotEmpty($parsed['password'] ?? '', "{$p} must yield a password");
        }
    }

    public function test_credential_is_persona_coherent(): void
    {
        $seed = 'hostZ';
        $ps = PersonaIdentity::fromSeed(PersonaIdentity::seedFromMaterial($seed));
        $b = $this->body($this->resp('/.vscode/sftp.json', $seed));
        $parsed = json_decode($b, true);
        self::assertSame($ps->field('db.user'), $parsed['username'] ?? null, 'username must be persona db.user');
        self::assertSame($ps->field('db.password'), $parsed['password'] ?? null, 'password must be persona db.password');
        self::assertStringContainsString((string) $ps->field('company.domain'), (string) ($parsed['host'] ?? ''), 'host must be persona-coherent');
        self::assertStringContainsString('/var/www/' . $ps->field('company.slug'), (string) ($parsed['remotePath'] ?? ''), 'remotePath must be the persona docroot');
    }

    public function test_credential_deploy_stable_but_varies_across_deploys(): void
    {
        self::assertSame($this->body($this->resp('/sftp.json', 'seedA')), $this->body($this->resp('/sftp.json', 'seedA')), 'byte-identical per deploy');
        self::assertNotSame($this->body($this->resp('/sftp.json', 'seedA')), $this->body($this->resp('/sftp.json', 'seedB')), 'varies across deploys (no fleet constant)');
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 400; $s++) {
            foreach (self::PATHS as $p) {
                $b = $this->body($this->resp($p, (string) $s));
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} {$p} denylist run");
            }
        }
    }

    public function test_no_reflection(): void
    {
        // The route render carries empty captures; nothing attacker-supplied enters the body.
        $b = $this->body($this->engine()->respond(new RequestContext('GET', '/.vscode/sftp.json', 'x=ZZCANARYZZ', [], null, 'x.test')));
        self::assertStringNotContainsString('ZZCANARYZZ', $b, 'no request byte may be reflected');
    }
}
