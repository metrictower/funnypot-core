<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;

/**
 * {{canned.*}} routes through DirectiveRenderer::identitySeed (FP-0277) — the SAME fold {{persona.*}}
 * uses — so canned identity tracks the per-deploy persona seed when wired, and degrades to the
 * per-request render seed when not. The exploit-confirmation markers survive on every path.
 */
final class DirectiveRendererCannedTest extends TestCase
{
    public function test_wired_persona_seed_makes_canned_deploy_stable_regardless_of_render_seed(): void
    {
        $personaSeed = 20260901;
        $rr = new DirectiveRenderer($personaSeed);
        // The render seed argument (per-request) must NOT change the canned bytes when a persona seed
        // is wired — canned identity is deploy-stable, exactly like persona identity.
        $atRenderSeedA = $rr->render('{{canned.passwd}}', [], 111);
        $atRenderSeedB = $rr->render('{{canned.passwd}}', [], 222);
        self::assertSame($atRenderSeedA, $atRenderSeedB, 'wired persona seed must ignore the per-request render seed');
        self::assertSame(CannedData::passwd($personaSeed), $atRenderSeedA);
        self::assertStringContainsString('root:x:0:0', $atRenderSeedA);
    }

    public function test_unwired_renderer_falls_back_to_the_render_seed(): void
    {
        // persona seed null (default) → canned resolves at the per-request render seed (the fail-safe
        // fallback FP-0276 shipped), byte-identical to calling the accessor with that seed.
        $rr = new DirectiveRenderer();
        self::assertSame(CannedData::passwd(777), $rr->render('{{canned.passwd}}', [], 777));
        self::assertStringContainsString('root:x:0:0', $rr->render('{{canned.passwd}}', [], 777));
    }

    public function test_two_deploys_give_different_canned_bytes_but_all_markers_survive(): void
    {
        $a = new DirectiveRenderer(1001);
        $b = new DirectiveRenderer(2002);

        foreach ([
            '{{canned.passwd}}' => 'root:x:0:0',
            '{{canned.shadow}}' => ':0:99999:7:::',
            '{{canned.group}}' => 'root:x:0:',
            '{{canned.environ}}' => 'PATH=',
            '{{canned.ssh_private_key}}' => '-----BEGIN OPENSSH PRIVATE KEY-----',
        ] as $directive => $marker) {
            $ra = $a->render($directive, [], 0);
            $rb = $b->render($directive, [], 0);
            self::assertNotSame($ra, $rb, "{$directive} must differ across deploy seeds");
            self::assertStringContainsString($marker, $ra, "{$directive} marker missing at deploy a");
            self::assertStringContainsString($marker, $rb, "{$directive} marker missing at deploy b");
        }

        // uid has a deliberately small supplementary-group tail (§5.4, not registered as a seeded
        // surface): its bytes MAY collide across two seeds, but the head marker survives on both.
        self::assertStringStartsWith('uid=0(root) gid=0(root) groups=0(root)', $a->render('{{canned.uid}}', [], 0));
        self::assertStringStartsWith('uid=0(root) gid=0(root) groups=0(root)', $b->render('{{canned.uid}}', [], 0));
    }
}
