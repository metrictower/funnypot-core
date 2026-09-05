<?php

declare(strict_types=1);

namespace Funnypot\Core\Reaction;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\BundleValidator;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Support\Chrome\Esc;
use Funnypot\Core\SynthesizedResponse;

/**
 * Appends a bounded, inert parameter reaction to an already-synthesized decoy route response — the
 * ONLY place a query intent turns into served bytes. It NEVER mutates the base response: it returns a
 * NEW SynthesizedResponse on success or null on any decline, so the caller keeps the exact base
 * response whenever this returns null. The whole method runs under catch(\Throwable) so a
 * renderer/encoder fault degrades to the base response, never a 5xx.
 *
 * THE REACTION IS A REFLECTING DECOY, gated exactly like one. It echoes attacker-chosen text (entity-
 * or byte-encoded) into a served body, so it is withheld unless
 *   config->paramReactivity && config->serveReflector('param-reaction', $request)
 * — and serveReflector AND-composes isolatedOrigin (operator intent), the per-class map, and the
 * request-bound authorizer (adapter evidence), each able only to subtract. An embedded host
 * (isolatedOrigin=false, the Laravel/WordPress/embedder default) can therefore NEVER echo, and the
 * position-blind synthesize() port ($request === null) carries no evidence and is always withheld —
 * only the respond() facade, which threads the live request, can serve a reaction. This mirrors the
 * attack/param reflecting-decoy tier one-for-one.
 *
 * TWO differential surfaces exist, both intended and neither an attacker-steerable oracle:
 *  - the code-owned $before/$after halves DO vary with the value's closed bucket (a passwd path vs an
 *    .env path); every bucket x seed grid is pinned fingerprint-clean by test, so a runtime scan of the
 *    halves is a belt-and-braces decline no attacker byte can steer;
 *  - the bundle `nf` re-check (via BundleValidator) DOES see the assembled body, and that is the ONE
 *    accepted differential — `nf` is the scanner's own negative matcher for this template (matcher
 *    truth for the scanner that sent the query), not detector vocabulary.
 * The fingerprint guard is NEVER run over the reflected value: doing so would make `?q=942100` decline
 * while `?q=842100` reacts, revealing a detector-keyed denylist — the exact tell the guard exists to
 * hide. The guard scans code-owned bytes only.
 *
 * 7.3-safe: classic constructor, docblocked properties; strpos/substr/strripos/preg_* only.
 */
final class ParamReactionDecorator
{
    /** The reflect class this decoration serves under (a code-defined class, never a compiled rule). */
    public const REFLECT_CLASS = 'param-reaction';

    /** Hard cap on the code+value fragment, independent of and below Config::$maxBodyBytes. */
    private const MAX_FRAGMENT_BYTES = 8192;

    /** Response headers that make an append unsafe or incoherent; presence declines (case-insensitive). */
    private const FORBIDDEN_HEADERS = [
        'location', 'refresh', 'set-cookie', 'content-disposition',
        'content-encoding', 'content-length', 'content-range', 'transfer-encoding',
    ];

    /** @var Config */
    private $config;

    /** @var int per-deploy identity seed for the renderer's closed cosmetic picks */
    private $deploySeed;

    /** @var ParamReactionRenderer */
    private $renderer;

    /** @var callable():?FingerprintGuard */
    private $guardLoader;

    /** @var bool whether the guard load has been attempted (a failure is cached, fail-closed) */
    private $guardLoaded = false;

    /** @var FingerprintGuard|null */
    private $guard;

    /**
     * @param callable():?FingerprintGuard|null $guardLoader test seam: defaults to the once-loaded,
     *        fail-closed package guard. Injected (not subclassed) so the class stays final.
     */
    public function __construct(Config $config, int $deploySeed, ?callable $guardLoader = null)
    {
        $this->config = $config;
        $this->deploySeed = $deploySeed;
        $this->renderer = new ParamReactionRenderer();
        $this->guardLoader = $guardLoader ?? static function (): ?FingerprintGuard {
            try {
                return FingerprintGuard::fromPackage();
            } catch (\Throwable $e) {
                return null;
            }
        };
    }

    /**
     * Return a decorated copy of $base, or null to keep the base response unchanged.
     *
     * @param array<string,mixed> $bundle the compiled bundle that produced $base
     */
    public function decorate(SynthesizedResponse $base, array $bundle, FakeHandle $handle, ?RequestContext $r): ?SynthesizedResponse
    {
        try {
            // 1. Gate — reflecting-decoy posture + a styled base to decorate.
            if (!$this->config->paramReactivity) {
                return null;
            }
            if (!$this->config->serveReflector(self::REFLECT_CLASS, $r)) {
                return null;
            }
            if ($this->config->responseStyle === Style::MINIMAL) {
                return null;
            }

            // 2. Handle + intent (public property, so revalidate a possibly host-built/forged intent).
            if ($handle->kind !== FakeHandle::KIND_ROUTE || !($handle->paramIntent instanceof ParamIntent)) {
                return null;
            }
            $intent = ParamIntent::tryFromArray($handle->paramIntent->toArray());
            if ($intent === null) {
                return null;
            }

            // 3. Status — no empty-body/redirect codes.
            $status = $base->status;
            if ($status < 200 || $status > 599 || $status === 204 || $status === 205 || ($status >= 300 && $status < 400)) {
                return null;
            }

            // 4. Bundle shape — any size/exclusive/regex/binary bundle is out of append scope.
            if (!empty($bundle['sz']) || !empty($bundle['x']) || !empty($bundle['rx']) || !empty($bundle['bin'])) {
                return null;
            }

            // 5. Content type — text/html or text/plain, no charset or utf-8 only.
            $mode = $this->contentMode($base->headers);
            if ($mode === null) {
                return null;
            }

            // 6. Headers — all plain strings, none active/framing.
            if (!$this->headersEligible($base->headers)) {
                return null;
            }

            // Render the code-owned halves and scan ONLY those (never the reflected value).
            $frag = $this->renderer->render($intent, $this->deploySeed, $mode);
            if ($frag === null) {
                return null;
            }
            $guard = $this->fingerprintGuard();
            if ($guard === null) {
                return null; // fail-closed: cannot verify => do not decorate
            }
            if ($guard->scan($frag->before) !== [] || $guard->scan($frag->after) !== []) {
                return null;
            }

            // Assemble: the value appears only in the single display slot, encoded for its context.
            $fragment = $this->assembleFragment($frag, $intent->value, $mode);
            if (strlen($fragment) > self::MAX_FRAGMENT_BYTES) {
                return null;
            }
            $finalBody = $mode === 'html'
                ? $this->insertHtml($base->body, $fragment)
                : $base->body . "\n" . $fragment;
            if (strlen($finalBody) > $this->config->maxBodyBytes) {
                return null;
            }

            // 7. Matcher truth — the assembled body must still satisfy the bundle (the ONE accepted
            // differential is `nf`; `bw` cannot be removed by an append, and headers are unchanged so
            // hw/hf/typed-header satisfaction is invariant by construction).
            if (!BundleValidator::satisfies($finalBody, $base->headers, $bundle)) {
                return null;
            }

            return new SynthesizedResponse($base->status, $base->headers, $finalBody, $base->satisfies);
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function assembleFragment(ReactionFragment $frag, string $value, string $mode): string
    {
        if (!$frag->usesValue) {
            return $frag->before;
        }
        $display = $mode === 'html' ? Esc::text($value) : TextDisplayEncoder::encode($value);

        return $frag->before . $display . $frag->after;
    }

    /** Insert before the LAST case-insensitive </body>; append when the base carries none. */
    private function insertHtml(string $body, string $fragment): string
    {
        $pos = strripos($body, '</body>');
        if ($pos === false) {
            return $body . $fragment;
        }

        return substr($body, 0, $pos) . $fragment . substr($body, $pos);
    }

    /**
     * 'html' or 'text' when the canonical Content-Type is text/html or text/plain (no charset or utf-8
     * only), else null — so a raw multibyte value in an HTML text node can never be mis-decoded.
     *
     * @param array<string,string|string[]> $headers
     */
    private function contentMode(array $headers): ?string
    {
        $ct = $this->headerValue($headers, 'content-type');
        if ($ct === null) {
            return null;
        }
        if (preg_match('~^text/(html|plain)\s*(;\s*charset=utf-8\s*)?$~i', $ct, $m) !== 1) {
            return null;
        }

        return strtolower($m[1]) === 'html' ? 'html' : 'text';
    }

    /**
     * Every header value is a plain string (a multi-line list value declines) and no active/framing
     * header is present.
     *
     * @param array<string,string|string[]> $headers
     */
    private function headersEligible(array $headers): bool
    {
        foreach ($headers as $name => $value) {
            if (!is_string($value)) {
                return false;
            }
            if (in_array(strtolower((string) $name), self::FORBIDDEN_HEADERS, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Case-insensitive header lookup returning a plain string value only (null when absent or a list).
     *
     * @param array<string,string|string[]> $headers
     */
    private function headerValue(array $headers, string $wanted): ?string
    {
        foreach ($headers as $name => $value) {
            if (strtolower((string) $name) === $wanted) {
                return is_string($value) ? $value : null;
            }
        }

        return null;
    }

    /** The runtime fingerprint guard, loaded once (a load failure cached), fail-closed on null. */
    private function fingerprintGuard(): ?FingerprintGuard
    {
        if (!$this->guardLoaded) {
            $this->guardLoaded = true;
            $this->guard = ($this->guardLoader)();
        }

        return $this->guard;
    }
}
