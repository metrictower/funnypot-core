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
 * FP-0512: the /.DS_Store binary disclosure decoy. A GET /.DS_Store serves a valid macOS Finder Bud1 blob
 * (not the generic CRS-LFI "failed to open stream" line, which a static server never emits) as
 * application/octet-stream. The blob is clean-room authored and was verified to round-trip through an
 * independent Bud1 parser at authoring time; here we assert the served bytes carry the Bud1 magic and the
 * buddy-allocator's structural markers, so a subtly-truncated or mis-encoded body (itself a tell) fails.
 */
final class DsStoreDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;
    /** @var array<string,Honeypot> */
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
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);

        return self::$engines[$seed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function serve(string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', '/.DS_Store', '', [], null, 'x.test'));
    }

    public function test_serves_octet_stream_200(): void
    {
        $r = $this->serve();
        self::assertNotNull($r, '/.DS_Store must serve a decoy, not fall to the 404/LFI line');
        self::assertSame(200, $r->status);
        self::assertSame('application/octet-stream', $r->headers['Content-Type'] ?? null);
    }

    public function test_body_is_a_valid_bud1_blob(): void
    {
        $body = (string) $this->serve()->body;
        // Bud1 header: 4-byte alignment magic then the "Bud1" buddy-allocator signature.
        self::assertSame("\x00\x00\x00\x01Bud1", substr($body, 0, 8), 'must carry the Bud1 magic');
        // Buddy-allocator structural markers that a truncated/malformed blob would lack.
        self::assertStringContainsString('DSDB', $body, 'the TOC directory marker must be present');
        self::assertStringContainsString('Iloc', $body, 'per-file Iloc records must be present');
        // A real .DS_Store is a multiple of the 4 KiB buddy block and never tiny.
        self::assertGreaterThanOrEqual(4096, strlen($body));
        self::assertSame(0, strlen($body) % 4, 'block-aligned length');
    }

    public function test_discloses_sibling_names(): void
    {
        // Bud1 stores filenames UTF-16BE; a couple of the seeded siblings must be present as the lure.
        $body = (string) $this->serve()->body;
        $utf16 = static fn (string $s): string => mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
        self::assertStringContainsString($utf16('backup'), $body, 'discloses the "backup" lure path');
        self::assertStringContainsString($utf16('config'), $body, 'discloses the "config" lure path');
    }

    public function test_body_is_deterministic_across_seeds(): void
    {
        // Static body_b64 (not a generator): byte-identical regardless of the per-request seed.
        self::assertSame((string) $this->serve('0')->body, (string) $this->serve('1')->body);
    }
}
