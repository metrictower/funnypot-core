<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests\Support\Chrome;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\Chrome\GenericSkin;
use Funnypot\Core\Support\Chrome\PageSlots;
use Funnypot\Core\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Core\Support\Chrome\Skin;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * FP-0283 — the class ↔ style coherence law, end-to-end over a full rendered document. The one prefix
 * source (VisualPersona::classPrefix(), one `$p` variable both the body and the <style> read in each
 * core skin) must produce exactly ONE prefix across the whole page, present on BOTH sides, and every
 * emitted prefixed class must be styled (except the documented -brand hook). The prefix scan is scoped
 * to `class="…"` attribute tokens and `<style>` selectors ONLY (Must-fix 3): a PhpMyAdmin document also
 * renders persona-derived text — a company slug DB name, fake table/host/person names — and a bare
 * `<word>-<4hex>` match over the whole document could false-hit one of those.
 */
final class SkinCoherenceTest extends TestCase
{
    private function genericSlots(): PageSlots
    {
        return PageSlots::fromArray([
            'app_name' => 'Portal',
            'page_title' => 'Users',
            'heading' => 'Users',
            'intro' => 'Recent activity across the tenant.',
            'nav_items' => ['Home', 'Reports', 'Settings'],
            'table' => ['cols' => ['User', 'Role'], 'rows' => [['a.hale', 'admin'], ['b.ng', 'ops']]],
            'form_fields' => ['Search'],
            'flash' => 'Saved.',
            'footer_note' => 'v1',
        ]);
    }

    private function pmaSlots(): PageSlots
    {
        return PageSlots::fromArray([
            'heading' => 'members',
            'intro' => 'Query results',
            'flash' => 'Query took 0.003s',
            'table' => ['cols' => ['id', 'email'], 'rows' => [['1', 'a@x.test'], ['2', 'b@x.test']]],
            'nav_items' => ['members', 'sessions', 'orders'],
        ]);
    }

    /** @return array{0:string,1:string} [styleBlock, bodyPart] */
    private function split(string $html): array
    {
        self::assertSame(1, preg_match('~<style>(.*?)</style>~s', $html, $m), 'document must carry one <style> block');
        $style = $m[1];
        $bodyPart = (string) substr($html, (int) strpos($html, '</style>') + strlen('</style>'));
        return [$style, $bodyPart];
    }

    /** Prefix tokens found in `class="…"` attributes of the body (scoped — not the whole document). */
    private function prefixesInClassAttrs(string $bodyPart): array
    {
        $prefixes = [];
        preg_match_all('/class="([^"]*)"/', $bodyPart, $attrs);
        foreach ($attrs[1] as $classAttr) {
            foreach (preg_split('/\s+/', trim($classAttr)) as $token) {
                if ($token !== '' && preg_match('/^([a-z]{2,3}-[0-9a-f]{4})-/', $token, $mm) === 1) {
                    $prefixes[$mm[1]] = true;
                }
            }
        }
        return $prefixes;
    }

    /** Prefix tokens found in `<style>` selectors only. */
    private function prefixesInStyle(string $style): array
    {
        $prefixes = [];
        preg_match_all('/\.([a-z]{2,3}-[0-9a-f]{4})-[a-z]/', $style, $m);
        foreach ($m[1] as $p) {
            $prefixes[$p] = true;
        }
        return $prefixes;
    }

    /**
     * @param array<string> $styledAllowlist suffixes emitted-but-unstyled by design (inherit a parent rule)
     * @dataProvider skins
     */
    public function test_one_prefix_per_document_present_on_both_sides(Skin $skin, string $slotsMethod, array $styledAllowlist): void
    {
        $slots = $this->{$slotsMethod}();
        for ($seed = 0; $seed < 64; $seed++) {
            $persona = VisualPersona::fromSeed($seed);
            $prefix = $persona->classPrefix();
            $html = $skin->render($slots, $persona, '/pma/index.php', '/pma');
            [$style, $body] = $this->split($html);

            $classPrefixes = $this->prefixesInClassAttrs($body);
            $stylePrefixes = $this->prefixesInStyle($style);

            self::assertSame([$prefix], array_keys($classPrefixes), "seed {$seed}: exactly one class-attr prefix, == classPrefix()");
            self::assertSame([$prefix], array_keys($stylePrefixes), "seed {$seed}: exactly one <style> selector prefix, == classPrefix()");

            // Every emitted prefixed class (in a class attribute) is styled, except the allowlist.
            preg_match_all('/class="([^"]*)"/', $body, $attrs);
            foreach ($attrs[1] as $classAttr) {
                foreach (preg_split('/\s+/', trim($classAttr)) as $token) {
                    if ($token === '' || strpos($token, $prefix . '-') !== 0) {
                        continue;
                    }
                    $suffix = substr($token, strlen($prefix) + 1);
                    if (in_array($suffix, $styledAllowlist, true)) {
                        continue;
                    }
                    // Boundary-aware: the selector `.token` followed by a rule/combinator char.
                    self::assertSame(
                        1,
                        preg_match('/\.' . preg_quote($token, '/') . '(?=[{ ,:])/', $style),
                        "seed {$seed}: emitted class {$token} must be styled in <style>"
                    );
                }
            }
        }
    }

    /** No document may carry a legacy fp- byte, and every rendered byte must pass the runtime
     *  FingerprintGuard (the verify-before-serve tail would otherwise DECLINE a colliding page). */
    public function test_no_legacy_prefix_or_denylist_hit_in_the_rendered_page(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach ([[new GenericSkin(), 'genericSlots'], [new PhpMyAdminSkin(), 'pmaSlots']] as [$skin, $slotsMethod]) {
            $slots = $this->{$slotsMethod}();
            for ($seed = 0; $seed < 128; $seed++) {
                $html = $skin->render($slots, VisualPersona::fromSeed($seed), '/pma/index.php', '/pma');
                self::assertStringNotContainsString('fp-', $html, "seed {$seed}: no legacy fp- class prefix");
                self::assertSame([], $guard->scan($html), "seed {$seed}: rendered page must be denylist-clean");
            }
        }
    }

    /** @return iterable<string,array{0:Skin,1:string,2:array<string>}> */
    public function skins(): iterable
    {
        // GenericSkin's only emitted-but-unstyled suffix is -brand (the header <span> inherits the
        // header rule — harmless, documented). PhpMyAdminSkin styles every class it emits.
        yield 'generic' => [new GenericSkin(), 'genericSlots', ['brand']];
        yield 'phpmyadmin' => [new PhpMyAdminSkin(), 'pmaSlots', []];
    }
}
