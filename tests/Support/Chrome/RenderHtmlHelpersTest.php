<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests\Support\Chrome;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\Chrome\AbstractSkin;
use Funnypot\Core\Support\Chrome\PageSlots;
use Funnypot\Core\Support\Chrome\Skin;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * FP-0283 — the RenderHtmlHelpers widget trait contract:
 *  - every prefixed class comes from the bound per-deploy prefix (bindClassPrefix() -> chromeClass());
 *    an UNBOUND widget throws (no fleet-constant `fp-` fallback can silently return);
 *  - class EMISSION and the widgetCss() <style> rules come from ONE accessor, so they cannot diverge;
 *  - the seeded prefix is denylist-clean over every reachable word × tail × suffix (the #1 concern —
 *    a collision would make the runtime verify-before-serve tail silently DECLINE a page).
 */
final class RenderHtmlHelpersTest extends TestCase
{
    private function probe(): ProbeSkin
    {
        return new ProbeSkin();
    }

    // --- unbound fails closed (no fp- fallback) ---------------------------------------------------

    public function test_every_prefixed_widget_throws_before_binding(): void
    {
        $calls = [
            'card' => static fn (ProbeSkin $s) => $s->card('h', 'b', 'x'),
            'pill' => static fn (ProbeSkin $s) => $s->pillHtml('L', 'ok'),
            'gauge' => static fn (ProbeSkin $s) => $s->gaugeHtml('L', 50, '5'),
            'sparkline' => static fn (ProbeSkin $s) => $s->sparklineHtml([1, 2, 3]),
            'breadcrumb' => static fn (ProbeSkin $s) => $s->breadcrumbHtml([['Home', '/'], ['Now', '#']]),
            'result' => static fn (ProbeSkin $s) => $s->controlResultCard('T', [['k', 'v']]),
            'pager' => static fn (ProbeSkin $s) => $s->pagerHtml('/p', 2, 3),
            'widgetCss' => static fn (ProbeSkin $s) => $s->widgetCss(),
            'chromeClass' => static fn (ProbeSkin $s) => $s->chromeClass('card'),
            'boundClassPrefix' => static fn (ProbeSkin $s) => $s->boundClassPrefix(),
        ];
        foreach ($calls as $name => $call) {
            $threw = false;
            try {
                $call($this->probe());
            } catch (\LogicException $e) {
                $threw = true;
            }
            self::assertTrue($threw, "{$name} must throw LogicException before bindClassPrefix()");
        }
    }

    // --- bind + chromeClass shape guards ----------------------------------------------------------

    public function test_bind_shape_guard_accepts_the_prefix_shape_and_rejects_unsafe_values(): void
    {
        $s = $this->probe();
        // A shape guard, NOT the literal lint: fp-1234 is accepted (the lint + G7 govern the literal).
        $s->bindClassPrefix('fp-1234');
        self::assertSame('fp-1234', $s->boundClassPrefix());
        $s->bindClassPrefix('ns-11a3');
        self::assertSame('ns-11a3', $s->boundClassPrefix());

        // Values carrying an attribute-breakout char or whitespace, or the wrong shape, are rejected —
        // this pins the "structurally inert in the attribute/selector sink" docblock claim.
        foreach (['Foo bar', 'x"onmouseover', "ns-11a3\ttab", 'ns-11a3<b', '', 'NS-11A3', 'ns_11a3', 'ns-11a'] as $bad) {
            $threw = false;
            try {
                $s->bindClassPrefix($bad);
            } catch (\LogicException $e) {
                $threw = true;
            }
            self::assertTrue($threw, "bindClassPrefix must reject " . var_export($bad, true));
        }
    }

    public function test_chrome_class_rejects_a_non_literal_suffix(): void
    {
        $s = $this->probe();
        $s->bindClassPrefix('ns-11a3');
        self::assertSame('ns-11a3-card', $s->chromeClass('card'));
        foreach (['Card', 'a b', 'a"b', '', '-x', '1x'] as $bad) {
            $threw = false;
            try {
                $s->chromeClass($bad);
            } catch (\LogicException $e) {
                $threw = true;
            }
            self::assertTrue($threw, "chromeClass must reject suffix " . var_export($bad, true));
        }
    }

    // --- prefix threads through every widget + class<->style coherence ----------------------------

    public function test_the_bound_prefix_threads_through_every_emitted_class(): void
    {
        for ($seed = 1; $seed <= 8; $seed++) {
            $prefix = VisualPersona::fromSeed($seed)->classPrefix();
            $html = $this->renderAllWidgets($prefix);

            self::assertStringNotContainsString('fp-', $html, "seed {$seed}: no legacy fp- byte may survive");
            // Every class token in the widget output starts with the bound prefix.
            self::assertGreaterThan(0, preg_match_all('/class="([^"]*)"/', $html, $m));
            foreach ($m[1] as $classAttr) {
                foreach (preg_split('/\s+/', trim($classAttr)) as $token) {
                    if ($token === '') {
                        continue;
                    }
                    self::assertStringStartsWith($prefix . '-', $token, "seed {$seed}: every widget class must carry the bound prefix");
                }
            }
        }
    }

    public function test_widget_css_selectors_all_carry_the_bound_prefix_and_cover_the_skin_styled_six(): void
    {
        $s = $this->probe();
        $prefix = VisualPersona::fromSeed(3)->classPrefix();
        $s->bindClassPrefix($prefix);
        $css = $s->widgetCss();

        // Exactly the six skin-styled suffixes, each under the bound prefix and no other prefix.
        preg_match_all('/\.([a-z0-9-]+)\{/i', $css, $m);
        $selectors = array_unique($m[1]);
        sort($selectors);
        $expected = array_map(static fn (string $x): string => $prefix . '-' . $x, ['card', 'card-body', 'card-header', 'dl', 'muted', 'pager']);
        sort($expected);
        self::assertSame($expected, $selectors, 'widgetCss must style exactly the six skin-styled classes under the bound prefix');

        // COHERENCE: the skin-styled classes card() + pagerHtml() emit are a subset of widgetCss selectors.
        $s2 = $this->probe();
        $s2->bindClassPrefix($prefix);
        $emitted = $s2->card('h', 'b', 'x') . $s2->pagerHtml('/p', 2, 3);
        preg_match_all('/class="([^"]*)"/', $emitted, $em);
        foreach ($em[1] as $classAttr) {
            foreach (preg_split('/\s+/', trim($classAttr)) as $token) {
                self::assertStringContainsString('.' . $token . '{', $css . '.', "emitted class {$token} must be styled by widgetCss");
            }
        }
    }

    // --- determinism / scope pin ------------------------------------------------------------------

    public function test_widgets_are_deterministic_and_only_the_class_bytes_vary_by_seed(): void
    {
        $prefixA = VisualPersona::fromSeed(1)->classPrefix();
        $prefixB = VisualPersona::fromSeed(2)->classPrefix();
        self::assertNotSame($prefixA, $prefixB);

        $a1 = $this->renderAllWidgets($prefixA);
        $a2 = $this->renderAllWidgets($prefixA);
        self::assertSame($a1, $a2, 'same prefix twice must be byte-identical');

        $b = $this->renderAllWidgets($prefixB);
        self::assertNotSame($a1, $b, 'two prefixes must differ in class bytes');

        // The inline colours are NOT seeded (scope pin): normalising the prefix away makes the two equal.
        $normA = str_replace($prefixA, 'PFX', $a1);
        $normB = str_replace($prefixB, 'PFX', $b);
        self::assertSame($normA, $normB, 'only the class prefix varies — inline widget styles are fixed');
    }

    // --- denylist sweep (P2, the #1 concern) ------------------------------------------------------

    /** The suffixes the core actually emits after the prefix: the 22 widget classes + the two core
     *  skins' vocabularies + the dangerous-looking probes a suffix could theoretically be. */
    private const CORE_SUFFIXES = [
        // RenderHtmlHelpers widgets
        'table', 'card', 'card-header', 'card-body', 'muted', 'pill', 'gauge-svg', 'gauge', 'gauge-text',
        'gauge-label', 'sparkline', 'breadcrumb', 'breadcrumb-sep', 'breadcrumb-link', 'breadcrumb-cur',
        'result-card', 'result-head', 'result-title', 'result-body', 'result-kv', 'dl', 'pager',
        // GenericSkin structural vocabulary
        'brand', 'app', 'crumbs', 'intro', 'form', 'flash',
        'header', 'topbar', 'masthead', 'banner', 'nav', 'menu', 'links', 'tabs',
        'box', 'panel', 'content', 'footer', 'foot', 'base', 'nav-list', 'menu-list', 'links-list', 'tabs-list',
        // PhpMyAdminSkin vocabulary
        'shell', 'tree', 'tree-title', 'db', 'tables', 'main', 'heading', 'notice', 'results-info', 'results',
        // adversarial probes — the only denylist tokens with letters a suffix could resemble
        'security', 'setup', 'mod',
    ];

    public function test_pool_words_are_wellformed_and_denylist_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach (PersonaIdentity::CLASS_PREFIX_WORDS as $word) {
            self::assertMatchesRegularExpression('/^[a-z]{2,3}$/', $word, "word {$word} shape");
            self::assertNotContains($word, ['fp', 'pma', 'wp'], "word {$word} must not be a product/funnypot signature");
            self::assertSame([], $guard->scan($word), "word {$word} must not scan dirty");
        }
    }

    public function test_no_reachable_word_tail_or_suffix_forms_a_denylisted_token(): void
    {
        $guard = FingerprintGuard::fromPackage();

        foreach (PersonaIdentity::CLASS_PREFIX_WORDS as $word) {
            // Exhaustive over ALL 65536 hex tails, bare prefix — the tail is the only free byte run, so
            // if no bare prefix trips the guard, no `\b9\d{5}\b` can form (4-char tail, digit-free word).
            for ($t = 0; $t <= 0xffff; $t++) {
                $prefix = $word . '-' . str_pad(dechex($t), 4, '0', STR_PAD_LEFT);
                if ($guard->scan($prefix) !== [] || SubSeed::hitsDeniedDigits($prefix)) {
                    self::fail("bare prefix {$prefix} is not denylist-clean");
                }
            }
            // Every core suffix (incl. the adversarial security/setup/mod probes) at 256 stepped tails —
            // a suffix can only add the literal `security`/`setup`, which none of these is, so a stepped
            // sweep over the tail space is exhaustive for the suffixed shape.
            foreach (self::CORE_SUFFIXES as $suffix) {
                for ($t = 0; $t <= 0xffff; $t += 257) {
                    $cls = $word . '-' . str_pad(dechex($t), 4, '0', STR_PAD_LEFT) . '-' . $suffix;
                    if ($guard->scan($cls) !== [] || SubSeed::hitsDeniedDigits($cls)) {
                        self::fail("class {$cls} is not denylist-clean");
                    }
                }
            }
        }
        self::assertTrue(true, 'every reachable word × tail × suffix is denylist-clean');
    }

    // --- harness ----------------------------------------------------------------------------------

    private function renderAllWidgets(string $prefix): string
    {
        $s = $this->probe();
        $s->bindClassPrefix($prefix);
        return $s->card('Header', 'Body', 'extra')
            . $s->pillHtml('Ready', 'ok')
            . $s->gaugeHtml('Load', 72, '182 kW')
            . $s->sparklineHtml([1, 5, 3, 9, 2])
            . $s->breadcrumbHtml([['Home', '/panel'], ['Logs', '/panel/logs'], ['Now', '#']])
            . $s->controlResultCard('Queued', [['id', '42'], ['state', 'ok']])
            . $s->pagerHtml('/panel/meters', 2, 5, 'Showing 26&ndash;50')
            . '<style>' . $s->widgetCss() . '</style>';
    }
}

/**
 * A minimal skin exposing the trait's protected widget/prefix helpers, mirroring the app's
 * WidgetProbeSkin shape. Extends AbstractSkin so it uses the RenderHtmlHelpers trait verbatim.
 */
final class ProbeSkin extends AbstractSkin implements Skin
{
    public function matches(string $path): bool
    {
        return true;
    }

    public function key(): string
    {
        return 'probe';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        $this->bindClassPrefix($persona->classPrefix());
        return $this->document('probe', $this->widgetCss(), $this->card('h', 'b'));
    }

    // Expose the protected trait surface for the contract test.
    public function bindClassPrefix(string $prefix): void
    {
        parent::bindClassPrefix($prefix);
    }

    public function boundClassPrefix(): string
    {
        return parent::boundClassPrefix();
    }

    public function chromeClass(string $suffix): string
    {
        return parent::chromeClass($suffix);
    }

    public function widgetCss(): string
    {
        return parent::widgetCss();
    }

    public function card(string $header, string $body, string $headerExtra = ''): string
    {
        return parent::card($header, $body, $headerExtra);
    }

    public function pillHtml(string $label, string $status): string
    {
        return parent::pillHtml($label, $status);
    }

    public function gaugeHtml(string $label, int $valuePct, string $text): string
    {
        return parent::gaugeHtml($label, $valuePct, $text);
    }

    /** @param list<int|float> $points */
    public function sparklineHtml(array $points): string
    {
        return parent::sparklineHtml($points);
    }

    /** @param list<array{0:string,1:string}> $crumbs */
    public function breadcrumbHtml(array $crumbs): string
    {
        return parent::breadcrumbHtml($crumbs);
    }

    /** @param list<array{0:string,1:string}> $detailPairs */
    public function controlResultCard(string $title, array $detailPairs): string
    {
        return parent::controlResultCard($title, $detailPairs);
    }

    public function pagerHtml(string $basePath, int $page, int $totalPages, string $summary = ''): string
    {
        return parent::pagerHtml($basePath, $page, $totalPages, $summary);
    }
}
