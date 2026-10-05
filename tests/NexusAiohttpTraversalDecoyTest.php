<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0457: Nexus (CVE-2024-4956) + aiohttp (CVE-2024-23334) URL-encoded path-traversal decoy.
 *
 * A file-download path bypass returns the raw file, so a path-based encoded traversal reaching
 * /etc/passwd (or win.ini) is served as application/octet-stream — matching the real products and the
 * Nettacker confirmation check — whereas the generic reflected LFI (attack-lfi-unix, text/plain) is
 * unchanged. The new rules (attack-nexus-traversal / -win) match two in:path conditions (AND) on the
 * RAW, still-encoded path: an encoded slash present AND the target file. Query-string LFI and a bare
 * /etc/passwd carry no `%2f` in the path, so they never match the new rules (no-regression).
 */
final class NexusAiohttpTraversalDecoyTest extends TestCase
{
    /** @var TemplateAttackEmulator|null */
    private static $em;

    /** @var array<string,mixed>|null */
    private static $idx;

    private static function emulator(): TemplateAttackEmulator
    {
        if (self::$em === null) {
            self::$em = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
        }

        return self::$em;
    }

    private function emulate(string $path): ?object
    {
        return self::emulator()->emulate(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    /** @return string[] */
    private function ids(?object $r): array
    {
        return $r !== null && isset($r->satisfies) ? $r->satisfies->templateIds() : [];
    }

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function respond(string $path, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    /** The documented Nexus wire-formats serve octet-stream passwd via the new rule. */
    public function test_nexus_probes_serve_octet_stream_passwd(): void
    {
        $forms = [
            '/%2f%2f%2f%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd', // ticket root form
            '/service/rest/swagger.json/..%2f..%2fetc/passwd',             // comments /service/rest form
            '/%2f%2e%2e%2fetc%2fpasswd',                                   // fully-encoded etc%2fpasswd
        ];
        foreach ($forms as $p) {
            $r = $this->emulate($p);
            self::assertNotNull($r, "{$p} must emulate a fake");
            self::assertSame(200, $r->status, "{$p} status");
            self::assertSame('application/octet-stream', $r->headers['Content-Type'] ?? null, "{$p} Content-Type");
            self::assertSame(1, preg_match('/root:.:0:0:/', (string) $r->body), "{$p} Nexus confirm regex root:.:0:0:");
            self::assertSame(1, preg_match('/root:.*:0:0:/', (string) $r->body), "{$p} AIOHTTP confirm regex root:.*:0:0:");
            self::assertSame(['attack-nexus-traversal'], $this->ids($r), "{$p} must be served by attack-nexus-traversal");
        }
    }

    /** Both canonical Nettacker probe shapes return 200 + matching regex. */
    public function test_both_nettacker_probe_shapes_return_200(): void
    {
        $nexus = $this->emulate('/%2f%2f%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd');
        $aiohttp = $this->emulate('/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd');
        foreach ([$nexus, $aiohttp] as $r) {
            self::assertNotNull($r);
            self::assertSame(200, $r->status);
            self::assertSame(1, preg_match('/root:.*:0:0:/', (string) $r->body));
        }
    }

    /** Every aiohttp static-prefix encoded-slash probe serves the passwd body (CVE-2024-23334). */
    public function test_aiohttp_static_prefixes_serve_passwd(): void
    {
        foreach (['static', 'assets', 'public', 'media', 'uploads', 'resources', 'build'] as $prefix) {
            $r = $this->emulate("/{$prefix}/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd");
            self::assertNotNull($r, "{$prefix} must emulate");
            self::assertSame(200, $r->status, "{$prefix} status");
            self::assertSame(1, preg_match('/root:.*:0:0:/', (string) $r->body), "{$prefix} passwd body");
            // The encoded-slash form carries %2f in the path, so the new octet-stream rule wins.
            self::assertSame('application/octet-stream', $r->headers['Content-Type'] ?? null, "{$prefix} Content-Type");
        }

        // The literal-slash aiohttp form has no %2f in the path -> stays attack-lfi-unix / text/plain.
        $lit = $this->emulate('/static/%2e%2e/%2e%2e/etc/passwd');
        self::assertNotNull($lit);
        self::assertSame(200, $lit->status);
        self::assertSame(1, preg_match('/root:.*:0:0:/', (string) $lit->body));
        self::assertSame(['attack-lfi-unix'], $this->ids($lit), 'literal-slash form must stay attack-lfi-unix');
    }

    /** Windows parity: a path-based encoded traversal to win.ini serves octet-stream. */
    public function test_nexus_win_ini_octet_stream(): void
    {
        $r = $this->emulate('/%2f%2f%2e%2e%2fwindows%2fwin.ini');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('application/octet-stream', $r->headers['Content-Type'] ?? null);
        self::assertStringContainsString('[extensions]', (string) $r->body);
        self::assertSame(['attack-nexus-traversal-win'], $this->ids($r));
    }

    /**
     * No-regression (AC4). The new rules need `%2f` in the PATH, so a query-string LFI and a bare
     * /etc/passwd cannot match them — each resolves exactly as it did before this change.
     */
    public function test_generic_lfi_and_direct_unchanged(): void
    {
        // Query-LFI: etc/passwd is in the query, not the path -> never the new rule. At emulate level the
        // in:request fold still routes it to attack-lfi-unix (the pre-existing behavior).
        $q = $this->emulate('/download?file=../../../../etc/passwd');
        self::assertSame(['attack-lfi-unix'], $this->ids($q), 'query-LFI must not be stolen by the new rule');

        // Direct /etc/passwd: no %2f -> not the new rule; emulate routes to attack-lfi-unix as before.
        $d = $this->emulate('/etc/passwd');
        self::assertSame(['attack-lfi-unix'], $this->ids($d), 'direct /etc/passwd must not be stolen by the new rule');
    }

    /** End-to-end: respond() (the real serve path, store+param+attack) serves the octet-stream fake. */
    public function test_respond_end_to_end_serves_octet_stream(): void
    {
        $r = $this->respond('/%2f%2f%2e%2e%2f%2e%2e%2fetc/passwd');
        self::assertNotNull($r, 'respond must serve a fake (not gate-suppressed)');
        self::assertSame(200, $r->status);
        self::assertSame('application/octet-stream', $r->headers['Content-Type'] ?? null);
        self::assertSame(1, preg_match('/root:.*:0:0:/', (string) $r->body));
    }

    /** AC6: served bodies/headers never carry a detector signature or form the bare 6-digit run. */
    public function test_fingerprint_safe_across_seeds(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $paths = ['/%2f%2e%2e%2fetc/passwd', '/static/%2e%2e%2fetc/passwd', '/%2f%2e%2e%2fwin.ini'];
        for ($s = 0; $s < 250; $s++) {
            foreach ($paths as $p) {
                $r = $this->respond($p, (string) $s);
                $b = (string) ($r->body ?? '');
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} {$p} formed a denylisted run");
                self::assertSame([], $guard->scanResponse($b, (array) ($r->headers ?? [])), "seed {$s} {$p} tripped FingerprintGuard");
            }
        }
    }
}
