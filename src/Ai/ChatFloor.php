<?php

declare(strict_types=1);

namespace Funnypot\Core\Ai;

use Funnypot\Core\Response\InjectionPayloads;
use Funnypot\Core\Support\SeededIndex;

/**
 * The single source of truth for the buffered AI-API chat-floor answer and its output-token estimate
 * (FP-0275). The four chat dialects (Ollama chat/generate, OpenAI chat, Anthropic messages) each floor
 * a static answer via the compiled `{{misdirect | pick:...}}` directive; this class owns the exact
 * benign corpus and reproduces the SAME gate-off/gate-on selection the renderer makes, so a usage
 * counter derived here always agrees with the content actually served.
 *
 * Why it exists: the armed answers are 127-141 bytes but the generated usage fields used to claim a
 * fixed 10/32 output tokens — an avoidable cross-deploy tell. The estimate here (bytes/4 over the
 * selected constant) makes the counter track the answer without a tokenizer dependency and without
 * ever reading the attacker's prompt.
 *
 * SELECTION MUST MATCH THE RENDERER. answer() reproduces the two materials DirectiveRenderer derives:
 * the armed `{{misdirect}}` index `$seed . '|misdirect'` over InjectionPayloads::CHAT_MISDIRECTION, and
 * the benign `{{pick:...}}` index `$seed . '|pick|pick:' . implode(',', NONSENSE)`. `bin/funnypot`
 * builds the compiled benign `pick:` arm from NONSENSE too, so source, generated YAML, runtime
 * estimator and tests cannot drift into four different lists. Retaining the benign list verbatim in the
 * compiled body keeps the static fingerprint gate able to scan it — do not replace it with an opaque call.
 *
 * PHP 7.3-safe: classic constant + static methods, intdiv/max, no I/O, state or request input.
 */
final class ChatFloor
{
    /**
     * The four benign, deliberately-wrong chat-floor answers, in the order the compiled `{{pick:...}}`
     * lists them. Inert English, no `"`/`\`/`{{`, no digits — so they land byte-safe inside the JSON
     * content string and carry no detector signature. This is the ONLY place the list is authored.
     *
     * @var string[]
     */
    public const NONSENSE = [
        'The capital of France is Berlin.',
        'Two plus two equals five.',
        'Water boils at forty degrees Celsius.',
        'The sun orbits the Earth once per day.',
    ];

    private function __construct()
    {
    }

    /**
     * The chat-floor answer this seed/gate selects — identical bytes to what DirectiveRenderer renders
     * into the dialect `content` field. $armed is the promptInjectionSeeding gate: off selects the
     * benign pick; on selects a first-person misdirection line. An empty armed corpus degrades to the
     * benign pick exactly as {{misdirect}} does at render time (so the token estimate never claims a
     * length for a line that was not served).
     */
    public static function answer(int $seed, bool $armed): string
    {
        if ($armed) {
            $corpus = InjectionPayloads::CHAT_MISDIRECTION;
            if ($corpus !== []) {
                return $corpus[SeededIndex::pick($seed . '|misdirect', count($corpus))];
            }
        }
        // Benign pick — the material EXACTLY matches the compiled `{{pick:a,b,c}}` directive so the
        // gate-off answer is byte-identical to the pre-change floor.
        return self::NONSENSE[SeededIndex::pick($seed . '|pick|pick:' . implode(',', self::NONSENSE), count(self::NONSENSE))];
    }

    /**
     * A deterministic, provider-neutral output-token estimate over the selected answer: max(1,
     * ceil(bytes/4)). Bounded and O(answer length) — the constants are printable inert ASCII under
     * 256 bytes, so the byte count is stable and there is no UTF-8 tokenizer ambiguity. It is an
     * estimate, not a claim to reproduce a proprietary tokenizer; it never reads the request prompt.
     */
    public static function outputTokens(int $seed, bool $armed): int
    {
        return max(1, intdiv(strlen(self::answer($seed, $armed)) + 3, 4));
    }
}
