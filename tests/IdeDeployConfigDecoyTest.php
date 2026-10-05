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
 * FP-0563: IDE/deploy-config exposure decoys. /.ftpconfig and /.idea/deployment.xml are enriched from their
 * degenerate corpus stubs into believable, parseable config leaking the deploy-stable persona SFTP identity
 * (coherent with /.vscode/sftp.json, /.env). /.idea/deployment.xml is guarded by route_key so its bundle
 * sibling /.idea/workspace.xml keeps its own body. Deploy-stable persona.* so the credential is correlatable
 * app-side and already fingerprint-safe; no request byte reflected, no real secret.
 */
final class IdeDeployConfigDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;
    /** @var array<string,Honeypot> */
    private static $engines = [];

    /** Persona (deploy-stable) derives from deploySeed, so a per-DEPLOY engine varies that, not the render salt. */
    private function engine(string $deploySeed = 'fixed'): Honeypot
    {
        if (isset(self::$engines[$deploySeed])) {
            return self::$engines[$deploySeed];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config(
            mode: 'respond',
            gate: static function (RequestContext $r): bool { return true; },
            pathScope: 'matched-only',
            personaSeed: static function (RequestContext $r): string { return 'req'; },
            severityCeiling: 'critical',
            deploySeed: $deploySeed,
        );

        return self::$engines[$deploySeed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function body(string $path, string $deploySeed = 'fixed'): object
    {
        $r = $this->engine($deploySeed)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
        self::assertNotNull($r, "{$path} must serve");

        return $r;
    }

    public function test_ftpconfig_is_valid_json_with_persona_credential(): void
    {
        $r = $this->body('/.ftpconfig');
        self::assertSame('application/json', $r->headers['Content-Type'] ?? null);
        $j = json_decode((string) $r->body, true);
        self::assertIsArray($j, '/.ftpconfig must be valid JSON (the stub is not)');
        self::assertSame('sftp', $j['protocol'] ?? null);
        self::assertNotSame('', (string) ($j['user'] ?? ''), 'carries a username');
        self::assertNotSame('', (string) ($j['passphrase'] ?? ''), 'carries a credential');
        self::assertStringStartsWith('deploy.', (string) ($j['host'] ?? ''));
        // corpus body-words preserved (the scanner's expected markers)
        foreach (['"protocol":', '"host":', '"user":', '"passphrase":'] as $w) {
            self::assertStringContainsString($w, (string) $r->body, "body-word {$w}");
        }
    }

    public function test_idea_deployment_is_well_formed_xml_leaking_identity(): void
    {
        $r = $this->body('/.idea/deployment.xml');
        self::assertStringStartsWith('text/xml', (string) ($r->headers['Content-Type'] ?? ''));
        $xml = simplexml_load_string((string) $r->body);
        self::assertNotFalse($xml, '/.idea/deployment.xml must be well-formed XML');
        foreach (['<?xml version=', '<project version', 'SFTP', '<login>', 'id_rsa'] as $w) {
            self::assertStringContainsString($w, (string) $r->body, "must leak {$w}");
        }
    }

    /** The route_key guard: the shared idea-folder-exposure bundle sibling must NOT be overwritten. */
    public function test_workspace_xml_not_shadowed_by_deployment_enrich(): void
    {
        $r = $this->body('/.idea/workspace.xml');
        self::assertStringNotContainsString('PublishConfigData', (string) $r->body, 'workspace.xml must keep its own body');
        self::assertStringNotContainsString('fileTransfer', (string) $r->body);
    }

    /** One credential story: /.ftpconfig and /.vscode/sftp.json name the same deploy-stable user. */
    public function test_credential_coherent_with_vscode_sftp(): void
    {
        $ftp = json_decode((string) $this->body('/.ftpconfig')->body, true);
        $vscode = json_decode((string) $this->body('/.vscode/sftp.json')->body, true);
        self::assertSame($vscode['username'] ?? 'x', $ftp['user'] ?? 'y', 'same identity across the leak surfaces');
    }

    public function test_deploy_stable_within_a_deploy(): void
    {
        // Deploy-stable (persona.*, not per-request fake.*): repeated requests on ONE deploy are byte-identical.
        $one = $this->body('/.ftpconfig', 'deploy-A');
        $two = $this->engine('deploy-A')->respond(new RequestContext('GET', '/.ftpconfig', '', [], null, 'y.test'));
        self::assertSame((string) $one->body, (string) $two->body, 'stable across requests within a deploy');
        // ...and it VARIES across deploys (the credential is distinct per deploy, not one shared constant).
        self::assertNotSame((string) $one->body, (string) $this->body('/.ftpconfig', 'deploy-B')->body, 'distinct per deploy');
    }

    public function test_fingerprint_safe_across_deploys(): void
    {
        for ($s = 0; $s < 200; $s++) {
            foreach (['/.ftpconfig', '/.idea/deployment.xml'] as $p) {
                $b = (string) $this->body($p, 'dep' . $s)->body;
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "deploy {$s} {$p} denylist run");
            }
        }
    }
}
