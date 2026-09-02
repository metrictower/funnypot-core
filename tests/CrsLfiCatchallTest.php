<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0190: the broad CRS traversal catch-all (priority 952) must NOT return /etc/passwd for an
 * unmapped target — the recognizable targets are owned by the higher-priority hand-authored LFI tier
 * (21-31), which still serves each target's own canned content. The catch-all serves a believable
 * "file absent" read for the long tail.
 */
final class CrsLfiCatchallTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private function serve(string $path, string $query): ?\Funnypot\Core\SynthesizedResponse
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED, [], null)
            ->emulate(new RequestContext('GET', $path, $query, [], null));
    }

    public function test_unmapped_traversal_does_not_return_passwd(): void
    {
        // A generic traversal to a target no hand-authored template owns -> the CRS catch-all.
        $r = $this->serve('/download.php', 'file=../../../../var/log/nginx/error.log');
        self::assertNotNull($r, 'the CRS traversal catch-all must still fire on an unmapped LFI probe');
        self::assertStringNotContainsString('root:x:0:0', $r->body, 'the catch-all must NOT leak /etc/passwd for an unmapped target');
        self::assertStringContainsString('No such file or directory', $r->body, 'unmapped LFI reads back a believable file-absent response');
    }

    public function test_etc_passwd_still_returns_passwd_via_the_hand_tier(): void
    {
        // The exact passwd target is owned by the hand-authored tier (31-lfi-unix, priority 31),
        // which wins first-match over the 952 catch-all — passwd is still served for a real passwd probe.
        $r = $this->serve('/download.php', 'file=../../../../etc/passwd');
        self::assertNotNull($r);
        self::assertStringContainsString('root:x:0:0', $r->body, 'a genuine /etc/passwd probe still gets the passwd canned content');
    }

    public function test_etc_shadow_still_owned_by_hand_tier(): void
    {
        // Another mapped target: shadow (28-lfi-shadow) — unaffected by the catch-all change.
        $r = $this->serve('/download.php', 'file=../../../../etc/shadow');
        self::assertNotNull($r);
        self::assertStringNotContainsString('No such file or directory', $r->body, 'a mapped target is served by its own hand template, not the catch-all');
    }
}
