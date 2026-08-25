<?php

declare(strict_types=1);

namespace Funnypot\Core\Response;

use Funnypot\Core\Template\DirectiveRenderer;

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
    /** @var RouteTemplateSet */
    private $set;

    /** @var DirectiveRenderer */
    private $renderer;

    public function __construct(
        RouteTemplateSet $set,
        ?DirectiveRenderer $renderer = null
    ) {
        $this->set = $set;
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
     * Append the "nice try" banner + ASCII troll in the file's own comment syntax, AFTER the body
     * so a human reads the (fabricated) secrets first and only then hits the taunt. Modes:
     *   - line:         each taunt line prefixed with the file's comment token (# , -- , ; )
     *   - block:        the taunt wrapped in one open/close comment ( <!-- … --> )
     *   - inline_field: a JSON string field after the opening brace ( "_comment": "…" ) — JSON has
     *                   no comment syntax, so this is the only way to keep the document parseable.
     *
     * @param array<string,mixed> $taunt
     */
    private function applyTaunt(string $body, array $taunt): string
    {
        $mode = (string) ($taunt['mode'] ?? 'line');
        // Banner text, a blank spacer, then the troll — all raw (no prefix yet).
        $lines = array_merge($this->tauntLines(), [''], $this->tauntArt());

        if ($mode === 'block') {
            $open = (string) ($taunt['open'] ?? '<!--');
            $close = (string) ($taunt['close'] ?? '-->');

            return $body . "\n" . $open . "\n" . implode("\n", $lines) . "\n" . $close . "\n";
        }

        if ($mode === 'inline_field') {
            // JSON: ride the taunt in as a string field so the document still parses. json_encode
            // handles the newlines / backslashes / quotes in the art.
            $key = (string) ($taunt['key'] ?? '_comment');
            $value = (string) json_encode(implode("\n", $lines), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $field = '  ' . (string) json_encode($key) . ': ' . $value . ',';
            $nl = strpos($body, "\n");
            if ($nl === false) {
                return $body;
            }

            return substr($body, 0, $nl + 1) . $field . "\n" . substr($body, $nl + 1);
        }

        // line mode: prefix each taunt line with the file's comment token so the doc still parses.
        $open = (string) ($taunt['open'] ?? '#');
        $commented = array_map(
            static function (string $l) use ($open): string {
                return $l === '' ? $open : $open . ' ' . $l;
            },
            $lines
        );

        return $body . "\n" . implode("\n", $commented) . "\n";
    }
}
