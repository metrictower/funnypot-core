<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Reaction\ParamIntent;
use Funnypot\Core\Reaction\ParamReactionRenderer;
use Funnypot\Core\Reaction\ReactionFragment;
use Funnypot\Core\Support\SubSeed;
use PHPUnit\Framework\TestCase;

/**
 * The renderer: deterministic per (deploy seed, kind, closed bucket), varies cosmetically across
 * deploy seeds, NEVER puts the value into the code-owned halves, and every code-owned half across all
 * kinds x buckets x a seed grid is fingerprint-clean. The last point is the load-bearing B1 guarantee:
 * because the display value is never in $before/$after, a runtime scan of the halves cannot be steered
 * by attacker bytes.
 */
final class ParamReactionRendererTest extends TestCase
{
    /** A fixed deploy-seed grid (ints, as Config::deploySeed() would supply). */
    private const SEEDS = [1, 7, 42, 101, 512, 1337, 65535, 99999, 271828, 314159, 1048576, 7654321, 33333333, 123456789, 987654321, 2000000000];

    private function renderer(): ParamReactionRenderer
    {
        return new ParamReactionRenderer();
    }

    /** Every closed bucket, one intent each, so the grid covers all code-owned pools. */
    private static function bucketSamples(): array
    {
        return [
            'file-passwd' => ParamIntent::create(ParamIntent::KIND_FILE_READ, 'file', '/etc/passwd'),
            'file-shadow' => ParamIntent::create(ParamIntent::KIND_FILE_READ, 'file', '/etc/shadow'),
            'file-hosts' => ParamIntent::create(ParamIntent::KIND_FILE_READ, 'file', '/etc/hosts'),
            'file-env' => ParamIntent::create(ParamIntent::KIND_FILE_READ, 'file', '/proc/self/environ'),
            'file-dotenv' => ParamIntent::create(ParamIntent::KIND_FILE_READ, 'path', '.env'),
            'file-wpconfig' => ParamIntent::create(ParamIntent::KIND_FILE_READ, 'path', 'wp-config.php'),
            'file-generic' => ParamIntent::create(ParamIntent::KIND_FILE_READ, 'file', '/var/www/settings.ini'),
            'redirect' => ParamIntent::create(ParamIntent::KIND_REDIRECT_NOTICE, 'url', 'https://evil.example/x'),
            'debug' => ParamIntent::create(ParamIntent::KIND_DEBUG_VIEW, 'debug', '1'),
            'cmd-id' => ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'id'),
            'cmd-whoami' => ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'whoami'),
            'cmd-uname' => ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'uname -a'),
            'cmd-pwd' => ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'pwd'),
            'cmd-ls' => ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'ls -la'),
            'cmd-cat' => ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'cat /etc/passwd'),
            'cmd-unknown' => ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'zzunknown'),
            'search' => ParamIntent::create(ParamIntent::KIND_SEARCH_RESULT, 'q', 'hello'),
        ];
    }

    public function test_render_is_deterministic_for_a_fixed_seed(): void
    {
        $renderer = $this->renderer();
        foreach (self::bucketSamples() as $label => $intent) {
            self::assertNotNull($intent, $label);
            foreach (['html', 'text'] as $mode) {
                $a = $renderer->render($intent, 424242, $mode);
                $b = $renderer->render($intent, 424242, $mode);
                self::assertNotNull($a, "{$label} {$mode}");
                self::assertEquals($a, $b, "{$label} {$mode} must be deterministic");
            }
        }
    }

    public function test_code_owned_halves_never_contain_the_value(): void
    {
        $renderer = $this->renderer();
        $sentinel = 'SENTINELxVALUExZZ';
        // Value-bearing kinds only (debug-view carries no slot).
        $intents = [
            ParamIntent::create(ParamIntent::KIND_FILE_READ, 'file', '/x/' . $sentinel),
            ParamIntent::create(ParamIntent::KIND_REDIRECT_NOTICE, 'url', 'https://' . $sentinel),
            ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', $sentinel),
            ParamIntent::create(ParamIntent::KIND_SEARCH_RESULT, 'q', $sentinel),
        ];
        foreach ($intents as $intent) {
            self::assertNotNull($intent);
            foreach (['html', 'text'] as $mode) {
                $frag = $renderer->render($intent, 42, $mode);
                self::assertNotNull($frag);
                self::assertStringNotContainsString($sentinel, $frag->before, 'value must not leak into $before');
                self::assertStringNotContainsString($sentinel, $frag->after, 'value must not leak into $after');
            }
        }
    }

    public function test_debug_view_uses_no_value_slot(): void
    {
        $intent = ParamIntent::create(ParamIntent::KIND_DEBUG_VIEW, 'debug', '1');
        self::assertNotNull($intent);
        foreach (['html', 'text'] as $mode) {
            $frag = $this->renderer()->render($intent, 42, $mode);
            self::assertNotNull($frag);
            self::assertFalse($frag->usesValue, "{$mode}: debug-view must not display the value");
            self::assertSame('', $frag->after, "{$mode}: no-slot fragment has an empty tail");
        }
    }

    public function test_every_half_is_fingerprint_clean_across_the_grid(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $renderer = $this->renderer();

        foreach (self::SEEDS as $seed) {
            foreach (self::bucketSamples() as $label => $intent) {
                self::assertNotNull($intent, $label);
                foreach (['html', 'text'] as $mode) {
                    $frag = $renderer->render($intent, $seed, $mode);
                    self::assertNotNull($frag, "{$label} {$mode} @ {$seed}");
                    self::assertSame([], $guard->scan($frag->before), "before dirty: {$label} {$mode} @ {$seed}");
                    self::assertSame([], $guard->scan($frag->after), "after dirty: {$label} {$mode} @ {$seed}");
                    // No generated digit run may form the denylisted bare-6-digit CRS-id token.
                    self::assertFalse(SubSeed::hitsDeniedDigits($frag->before), "before digits: {$label} {$mode} @ {$seed}");
                    self::assertFalse(SubSeed::hitsDeniedDigits($frag->after), "after digits: {$label} {$mode} @ {$seed}");
                }
            }
        }
    }

    /**
     * @dataProvider varyingKindProvider
     */
    public function test_cosmetics_vary_across_deploy_seeds(string $label, ?ParamIntent $intent): void
    {
        self::assertNotNull($intent, $label);
        $renderer = $this->renderer();
        $seen = [];
        foreach (self::SEEDS as $seed) {
            $frag = $renderer->render($intent, $seed, 'html');
            self::assertNotNull($frag);
            $seen[$frag->before . '|' . $frag->after] = true;
        }
        self::assertGreaterThanOrEqual(2, count($seen), "{$label} must vary across deploy seeds");
    }

    /** @return iterable<string,array{0:string,1:?ParamIntent}> */
    public static function varyingKindProvider(): iterable
    {
        yield 'file-passwd' => ['file-passwd', ParamIntent::create(ParamIntent::KIND_FILE_READ, 'file', '/etc/passwd')];
        yield 'redirect' => ['redirect', ParamIntent::create(ParamIntent::KIND_REDIRECT_NOTICE, 'url', 'https://x/y')];
        yield 'debug' => ['debug', ParamIntent::create(ParamIntent::KIND_DEBUG_VIEW, 'debug', '1')];
        yield 'cmd-ls' => ['cmd-ls', ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'ls')];
        yield 'search' => ['search', ParamIntent::create(ParamIntent::KIND_SEARCH_RESULT, 'q', 'x')];
    }

    public function test_reaction_fragment_forces_empty_tail_when_value_unused(): void
    {
        // Belt-and-braces on the value object itself: usesValue=false zeroes $after even if passed.
        $frag = new ReactionFragment('before', 'IGNORED', false);
        self::assertSame('', $frag->after);
    }
}
