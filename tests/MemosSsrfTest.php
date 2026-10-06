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
 * FP-0384 — the Memos knowledge-base SSRF decoy (CVE-2025-22952): the 500 connection-refused differential
 * the Nettacker detector keys on, and the IMDS pivot (dead {{fake.*}} creds). Zero-egress by construction.
 */
final class MemosSsrfTest extends TestCase
{
    /** @var array<string,mixed> */
    private static function index(): array
    {
        return require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    }

    private function engine(string $seed = 'fixed'): Honeypot
    {
        $cfg = new Config(
            'respond',
            static fn (RequestContext $r): bool => true,
            'matched-only',
            static fn (RequestContext $r): string => 'fixed',
            'coherent',
            Style::REALISTIC,
            'high',
            65536, 0, 0, false, null, null, null, $seed
        );
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    private function resp(string $query, string $path = '/api/v1/markdown/link:metadata'): ?object
    {
        return $this->engine()->respond(new RequestContext('GET', $path, $query, [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_localhost_probe_is_the_nettacker_differential(): void
    {
        $r = $this->resp('link=http://localhost:13042');
        self::assertSame(500, $r->status ?? null);
        self::assertSame('application/json', $r->headers['Content-Type'] ?? null);
        $b = $this->body($r);
        // Nettacker: (?s)(?=.*localhost:13042)(?=.*connect: connection refused)
        self::assertStringContainsString('localhost:13042', $b);
        self::assertStringContainsString('connect: connection refused', $b);
        self::assertStringContainsString('dial tcp', $b);
    }

    public function test_500_body_reflects_attacker_host_and_is_valid_json(): void
    {
        $r = $this->resp('link=http://evil.example:9999/x');
        $b = $this->body($r);
        self::assertStringContainsString('evil.example:9999', $b, 'names the attacker target like the real Go error');
        self::assertNotNull(json_decode($b), 'the error body is valid JSON');
    }

    public function test_hostile_link_cannot_break_the_json(): void
    {
        // A quote-injection attempt in the link: the charset-limited capture keeps %22 literal (no decode),
        // so the JSON stays well-formed and un-injected.
        $r = $this->resp('link=http://evil%22.example/%22%7D');
        $b = $this->body($r);
        self::assertNotNull(json_decode($b), 'percent-encoded quotes stay literal; JSON is not broken');
        self::assertStringNotContainsString('"}' . "\n" . '"', $b);
    }

    public function test_imds_credentials_leaf_pivots_to_dead_sts(): void
    {
        $r = $this->resp('link=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role');
        self::assertSame(200, $r->status ?? null);
        $b = $this->body($r);
        self::assertStringContainsString('"AccessKeyId" : "ASIA', $b, 'dead STS access key');
        self::assertStringContainsString('SecretAccessKey', $b);
        self::assertStringNotContainsString('connection refused', $b, 'the IMDS branch is a 200, not the 500');
    }

    public function test_imds_metadata_tree_pivots_to_listing(): void
    {
        $r = $this->resp('link=http://169.254.169.254/latest/meta-data/');
        self::assertSame(200, $r->status ?? null);
        $b = $this->body($r);
        self::assertStringContainsString('instance-id', $b);
        self::assertStringContainsString('iam/', $b);
    }

    public function test_non_memos_path_with_link_does_not_match(): void
    {
        // A different /api/v1 path must not false-positive into the SSRF decoy.
        $r = $this->resp('link=http://localhost:13042', '/api/v1/nodes');
        self::assertStringNotContainsString('connect: connection refused', $this->body($r));
    }

    public function test_memos_path_without_link_does_not_match(): void
    {
        $r = $this->resp('');
        self::assertStringNotContainsString('connect: connection refused', $this->body($r));
    }
}
