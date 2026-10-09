<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Decoy;

use PHPUnit\Framework\TestCase;

/**
 * The shipped chain must be exactly the bytes its manifest describes, and the manifest must record
 * the safety facts the build script asserted. A rebuild updates both files together.
 */
final class DecoyChainManifestTest extends TestCase
{
    public function test_chain_matches_its_manifest(): void
    {
        $dir = __DIR__ . '/../../resources/decoy';
        $bytes = (string) file_get_contents($dir . '/chain.7z');
        $m = json_decode((string) file_get_contents($dir . '/chain.json'), true);

        self::assertIsArray($m);
        self::assertSame(strlen($bytes), $m['bytes']);
        self::assertSame(hash('sha256', $bytes), $m['sha256']);
        self::assertSame("7z\xBC\xAF\x27\x1C", substr($bytes, 0, 6));
        self::assertLessThanOrEqual(1150000, $m['bytes']);
        self::assertGreaterThanOrEqual(500, $m['depth']);
        self::assertSame(1, $m['stats']['symlinks']);
        self::assertGreaterThan($m['depth'], $m['claimed_parts']);
    }

    public function test_raw_chain_bytes_expose_no_bait_text(): void
    {
        $bytes = (string) file_get_contents(__DIR__ . '/../../resources/decoy/chain.7z');
        foreach (['PASSWORD', 'BEGIN OPENSSH', 'Part ', 'rotated', 'aws_secret', 'wp_users'] as $marker) {
            self::assertFalse(strpos($bytes, $marker), $marker);
        }
    }
}
