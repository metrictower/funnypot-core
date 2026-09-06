<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\BundleValidator;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;

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
            'respond',                                                        // mode
            static function (RequestContext $r): bool { return true; },       // gate
            'matched-only',                                                   // pathScope
            static function (RequestContext $r): string { return 'fixed'; },  // personaSeed
            'coherent',                                                       // personaBreadth
            $style                                                            // responseStyle
        ));
    }

    /** The company domain the coherent persona projects for this suite's deploy seed. */
    private function personaDomain(): string
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'fixed'; },
            'coherent',
            Style::REALISTIC
        );

        return (string) PersonaIdentity::fromSeed($config->deploySeed())->field('company.domain');
    }

    public function test_realistic_git_config_is_rich_but_still_satisfies(): void
    {
        $r = $this->inverter(Style::REALISTIC)->respond(new RequestContext('GET', '/.git/config'));

        self::assertNotNull($r);
        // Rich: a full config, not just the bare token — the decoy remote is on the persona domain,
        // never a fixed placeholder (a lure naming another company than the host is a fingerprint).
        self::assertStringContainsString('[remote "origin"]', $r->body);
        self::assertStringContainsString('git.' . $this->personaDomain() . '/internal/', $r->body);
        self::assertStringNotContainsStringIgnoringCase('git.example.com', $r->body);
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
