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
 * FP-0570: the /.ssh/id_rsa exposed-SSH-private-key canary. A per-deploy INERT OpenSSH private key —
 * seed-derived (never a fleet-constant key in this PUBLIC repo), parse-plausible (the openssh-key-v1
 * magic + 70-col-wrapped base64) but not a usable key, so no real credential leaks and a worm that
 * exfiltrates+replays it is recognisable app-side as having walked our planted canary.
 */
final class SshKeyCanaryTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
            static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, 'fixed');

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function serve(string $method, string $host): ?object
    {
        return $this->engine()->respond(new RequestContext($method, '/.ssh/id_rsa', '', [], null, $host));
    }

    public function test_serves_a_believable_openssh_private_key(): void
    {
        $r = $this->serve('GET', 'scan.example.test');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('text/plain; charset=utf-8', $r->headers['Content-Type'] ?? $r->headers['content-type'] ?? '');
        self::assertStringContainsString("-----BEGIN OPENSSH PRIVATE KEY-----\n", $r->body);
        self::assertStringContainsString("-----END OPENSSH PRIVATE KEY-----\n", $r->body);
        // Parse-plausible: the base64 body decodes to the real OpenSSH magic prefix.
        preg_match('/-----BEGIN OPENSSH PRIVATE KEY-----\n(.*)\n-----END/s', $r->body, $m);
        $decoded = base64_decode(str_replace("\n", '', $m[1]), true);
        self::assertIsString($decoded);
        self::assertStringStartsWith("openssh-key-v1\x00", (string) $decoded, 'carries the openssh-key-v1 magic');
    }

    public function test_head_is_answered(): void
    {
        $r = $this->serve('HEAD', 'scan.example.test');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
    }

    public function test_key_is_per_deploy_not_a_fleet_constant(): void
    {
        // Per-deploy variance + determinism are a PERSONA-SEED axis (the served key is deploy-stable for
        // one Config), so assert at the persona level across distinct deploy seeds.
        $a = (string) PersonaIdentity::fromSeed(1)->field('ssh.privateKey');
        $b = (string) PersonaIdentity::fromSeed(2)->field('ssh.privateKey');
        self::assertNotSame($a, $b, 'different deploys must derive DIFFERENT keys (no static fleet key)');
        self::assertSame($a, (string) PersonaIdentity::fromSeed(1)->field('ssh.privateKey'), 'same deploy -> same key');
    }

    public function test_key_is_denylist_clean_and_well_formed_across_many_seeds(): void
    {
        // The regenerate-until-clean guarantee: no deploy seed produces a bare 9\d{5} CRS-rule-id collision,
        // and every seed yields a plausible openssh-key-v1 PEM.
        for ($seed = 0; $seed < 128; $seed++) {
            $key = (string) PersonaIdentity::fromSeed($seed)->field('ssh.privateKey');
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $key), "seed {$seed}: key blob must be denylist-clean");
            self::assertStringContainsString('-----BEGIN OPENSSH PRIVATE KEY-----', $key, "seed {$seed}: valid PEM frame");
            preg_match('/KEY-----\n(.*)\n-----END/s', $key, $m);
            self::assertStringStartsWith("openssh-key-v1\x00", (string) base64_decode(str_replace("\n", '', $m[1]), true), "seed {$seed}: magic");
        }
    }
}
