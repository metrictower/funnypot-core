<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Response\BundleValidator;
use Funnypot\Response\Style;
use Funnypot\Store\PhpArrayStore;

use PHPUnit\Framework\TestCase;

final class EmulatorTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    private function inverter(string $style): Honeypot
    {
        return new Honeypot($this->store(), new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,
            responseStyle: $style,
            personaSeed: static fn (RequestContext $r): string => 'fixed'
        ));
    }

    public function test_realistic_git_config_is_rich_but_still_satisfies(): void
    {
        $r = $this->inverter(Style::REALISTIC)->respond(new RequestContext('GET', '/.git/config'));

        self::assertNotNull($r);
        // Rich: a full config, not just the bare token.
        self::assertStringContainsString('[remote "origin"]', $r->body);
        self::assertStringContainsString('git.example.com', $r->body);
        // Still satisfies the matcher: required token present, forbidden absent.
        self::assertStringContainsString('[core]', $r->body);
        self::assertStringNotContainsStringIgnoringCase('<html', $r->body);
        // No real credentials leaked in the decoy remote URL.
        self::assertStringNotContainsString('@', explode("\n", $r->body)[6] ?? '');
    }

    public function test_taunt_style_carries_a_marker_and_still_satisfies(): void
    {
        $r = $this->inverter(Style::TAUNT)->respond(new RequestContext('GET', '/.git/config'));

        self::assertNotNull($r);
        self::assertStringContainsStringIgnoringCase('nice try', $r->body);
        self::assertStringContainsString('[core]', $r->body);
    }

    public function test_minimal_style_stays_terse(): void
    {
        $r = $this->inverter(Style::MINIMAL)->respond(new RequestContext('GET', '/.git/config'));

        self::assertNotNull($r);
        self::assertStringContainsString('[core]', $r->body);
        self::assertStringNotContainsString('[remote "origin"]', $r->body);
    }

    public function test_no_emulator_falls_back_to_minimal(): void
    {
        // webpack-config has no emulator -> realistic style yields the minimal body.
        $r = $this->inverter(Style::REALISTIC)->respond(new RequestContext('GET', '/webpack.config.js'));

        self::assertNotNull($r);
        self::assertStringContainsString('module.exports', $r->body);
    }

    public function test_realistic_output_is_deterministic_per_seed(): void
    {
        $a = $this->inverter(Style::REALISTIC)->respond(new RequestContext('GET', '/.git/config'));
        $b = $this->inverter(Style::REALISTIC)->respond(new RequestContext('GET', '/.git/config'));

        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body);
    }

    public function test_bundle_validator_catches_missing_and_forbidden(): void
    {
        $bundle = ['bw' => ['NEEDED'], 'nf' => ['BANNED']];

        self::assertTrue(BundleValidator::satisfies("has NEEDED here", [], $bundle));
        self::assertFalse(BundleValidator::satisfies("missing token", [], $bundle));
        self::assertFalse(BundleValidator::satisfies("NEEDED but also BANNED", [], $bundle));
    }
}
