<?php

declare(strict_types=1);

namespace Funnypot\Response;

use Funnypot\Template\DirectiveRenderer;

/**
 * One data-driven endpoint emulator, replacing all the hand-coded Response\Emulator
 * classes. It looks up the matching route template for a served bundle and renders its
 * authored body/headers through the bounded DirectiveRenderer, deriving realistic and
 * taunt styles from a single authored body.
 *
 * Correctness is guaranteed DOWNSTREAM, not by the template: ResponseSynthesizer re-runs
 * BundleValidator + typed-header + regex/size checks on this output and falls back to
 * minimal synthesis on any mismatch — so a badly authored body degrades to minimal, it
 * can never break a matcher. appendMissingTokens() is the belt-and-braces: every required
 * body word is guaranteed present regardless of what the author wrote.
 */
final class RouteTemplateEmulator extends AbstractEmulator
{
    private DirectiveRenderer $renderer;

    public function __construct(
        private RouteTemplateSet $set,
        ?DirectiveRenderer $renderer = null
    ) {
        $this->renderer = $renderer ?? new DirectiveRenderer();
    }

    public function supports(array $bundle): bool
    {
        return $this->set->findRule($bundle) !== null;
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $rule = $this->set->findRule($bundle);
        if ($rule === null) {
            return null;
        }

        // Routes have no attacker payload, so captures are empty (seed-only directives).
        $body = $this->renderer->render((string) ($rule['body'] ?? ''), [], $seed);

        $headers = [];
        foreach ((array) ($rule['headers'] ?? []) as $name => $value) {
            $headers[(string) $name] = $this->renderer->render((string) $value, [], $seed);
        }

        // A per-request session cookie (fresh random value) — a login/app page that never sets
        // one, or sets a static shared one, is a classic honeypot tell. Only templates that opt
        // in (real stateful apps) get it; static-file exposures never do.
        if (!empty($rule['set_cookie'])) {
            $headers['Set-Cookie'] = $rule['set_cookie'] . '=' . bin2hex(random_bytes(16)) . '; path=/; HttpOnly';
        }

        if ($style === Style::TAUNT && isset($rule['taunt'])) {
            $body = $this->applyTaunt($body, (array) $rule['taunt']);
        }

        // Guarantee every required token survives, whatever the author (or the banner) did.
        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, $headers);
    }

    /**
     * Prepend the "nice try" banner in the file's own comment syntax. Modes:
     *   - line:         per-line prefix (# , -- )
     *   - block:        one flattened comment ( <!-- … --> )
     *   - inline_field: a JSON field inserted after the opening brace ( "_comment": "…" )
     *
     * @param array<string,mixed> $taunt
     */
    private function applyTaunt(string $body, array $taunt): string
    {
        $mode = (string) ($taunt['mode'] ?? 'line');

        if ($mode === 'block') {
            $open = (string) ($taunt['open'] ?? '<!--');
            $close = (string) ($taunt['close'] ?? '-->');

            return $open . ' ' . str_replace("\n", ' ', $this->tauntBanner('')) . ' ' . $close . "\n" . $body;
        }

        if ($mode === 'inline_field') {
            $key = (string) ($taunt['key'] ?? '_comment');
            $note = trim(str_replace('"', "'", str_replace("\n", ' ', $this->tauntBanner(''))));
            $field = '  "' . $key . '": "' . $note . '",';
            $nl = strpos($body, "\n");
            if ($nl === false) {
                return $body;
            }

            return substr($body, 0, $nl + 1) . $field . "\n" . substr($body, $nl + 1);
        }

        // line mode
        $open = (string) ($taunt['open'] ?? '#');

        return $this->tauntBanner($open) . "\n" . $body;
    }
}
