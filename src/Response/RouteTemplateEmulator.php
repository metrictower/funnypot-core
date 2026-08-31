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

    /** @var bool opt-in LLM prompt-injection seeding gate (FP-0239); false ⇒ no injection block. */
    private $promptInjectionSeeding;

    /** @var array<string,string> operator canary map (e.g. ['beacon' => '<self-beacon url>']); empty ⇒ no URL. */
    private $beaconCanary;

    /**
     * @param array<string,string> $beaconCanary
     */
    public function __construct(
        RouteTemplateSet $set,
        ?DirectiveRenderer $renderer = null,
        bool $promptInjectionSeeding = false,
        array $beaconCanary = []
    ) {
        $this->set = $set;
        $this->renderer = $renderer ?? new DirectiveRenderer();
        $this->promptInjectionSeeding = $promptInjectionSeeding;
        $this->beaconCanary = $beaconCanary;
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

        // Routes have no attacker payload, so captures are empty (seed-only directives). The 4th arg
        // is the operator canary map — empty on the default path (byte-identical to pre-FP-0239), and
        // carries the self-beacon URL only when prompt-injection seeding is configured on.
        $body = $this->renderer->render((string) ($rule['body'] ?? ''), [], $seed, $this->beaconCanary);

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

        // FP-0239: inert prompt-injection + self-beacon seeding, gated ORTHOGONALLY to Style::TAUNT
        // (so a deploy can beacon without the visible troll-face). It reuses the rule's taunt carrier
        // metadata (mode/open/close) but fires under its own opt-in config gate — the flag is consulted
        // HERE, inside the emulator, only because it was threaded Config → Honeypot →
        // EmulatorRegistry::default() → this ctor.
        if ($this->promptInjectionSeeding && isset($rule['taunt'])) {
            $body = $this->applyInjection($body, (array) $rule['taunt'], $seed);
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

    /**
     * Append the INERT prompt-injection block (FP-0239) after the body, in the file's own comment
     * syntax — modelled on applyTaunt(), same three modes (line / block / inline_field). The payload
     * is authored plain-text constants (InjectionPayloads); the ONLY dynamic value is the self-beacon
     * URL, substituted from the server-signed operator canary map via {{canary.beacon}} — and the
     * beacon line is included ONLY when a beacon is configured, so no URL ever appears otherwise.
     *
     * There is no attacker-byte reflection here: the route render passes empty captures and the block
     * is built from constants + a server-derived canary, so an attacker request byte can never land in
     * it. The block stays well under the 2 KB budget; ResponseSynthesizer's size/validator gate is the
     * downstream backstop regardless.
     *
     * @param array<string,mixed> $taunt the rule's taunt carrier metadata (mode/open/close), reused
     */
    private function applyInjection(string $body, array $taunt, int $seed): string
    {
        $lines = InjectionPayloads::MISDIRECTION;
        // Only emit the self-beacon line when an operator beacon URL is actually configured (invariant:
        // rendering with no beacon config emits no URL). {{canary.beacon}} resolves from the map.
        if (($this->beaconCanary['beacon'] ?? '') !== '') {
            $lines[] = $this->renderer->render(InjectionPayloads::BEACON_TEMPLATE, [], $seed, $this->beaconCanary);
        }

        $mode = (string) ($taunt['mode'] ?? 'line');

        if ($mode === 'block') {
            $open = (string) ($taunt['open'] ?? '<!--');
            $close = (string) ($taunt['close'] ?? '-->');

            return $body . "\n" . $open . "\n" . implode("\n", $lines) . "\n" . $close . "\n";
        }

        if ($mode === 'inline_field') {
            // JSON: ride the block in as one string field so the document still parses. A DISTINCT key
            // from the taunt's (fixed '_assessment') so a rule that also emits a taunt _comment (both
            // features on at once) does not produce a duplicate key.
            $value = (string) json_encode(implode(' ', $lines), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $field = '  ' . (string) json_encode('_assessment') . ': ' . $value . ',';
            $nl = strpos($body, "\n");
            if ($nl === false) {
                return $body;
            }

            return substr($body, 0, $nl + 1) . $field . "\n" . substr($body, $nl + 1);
        }

        // line mode: prefix each line with the file's comment token so the doc still parses.
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
