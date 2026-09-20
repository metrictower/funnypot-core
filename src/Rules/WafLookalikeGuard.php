<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

use RuntimeException;

/**
 * WAF/antibot CHALLENGE-PAGE guard — a CI/TEST-ONLY scanner that fails the build if any served
 * string resembles a WAF block/challenge interstitial (a branded footer, the antibot spinner
 * markup, a proof-of-work loop, a "checking your browser" body, a redirect into a /challenge page).
 * Serving such a page would break the deception and signal that something is watching.
 *
 * DELIBERATELY NOT a runtime guard, and deliberately minimal (fromPackage + scan only): unlike
 * Compiler\Crs\FingerprintGuard it has no scanResponse/assertResponseClean/tryFromPackage and is
 * referenced by NO src/ runtime path — only scripts/ci/check-fingerprint-safety.php and its unit
 * test. Keeping it out of every runtime path is what preserves the "no runtime behaviour change"
 * invariant: its tells live in resources/waf-lookalike-tells.php, separate from the runtime egress
 * denylist. 7.3-clean.
 */
final class WafLookalikeGuard
{
    /** @var string[] */
    private $literals;

    /** @var string[] */
    private $patterns;

    /**
     * @param string[] $literals case-insensitive substrings that must not appear
     * @param string[] $patterns regex signatures (no delimiters) that must not match
     */
    public function __construct(array $literals, array $patterns)
    {
        $this->literals = $literals;
        $this->patterns = $patterns;
    }

    /**
     * Load the tracked tell list bundled with the package. A missing file, or a present-but-empty
     * list (both literals AND patterns empty — e.g. a resource truncated to no `return`), throws
     * rather than silently building a no-op guard that would pass every response as clean: a CI
     * gate relying on this must fail CLOSED on a broken list, never fail open.
     */
    public static function fromPackage(): self
    {
        $file = dirname(__DIR__, 2) . '/resources/waf-lookalike-tells.php';
        if (!is_file($file)) {
            throw new RuntimeException('WAF-lookalike tell list resource missing: ' . $file);
        }

        $tells = require $file;
        $literals = is_array($tells) ? (array) ($tells['literals'] ?? []) : [];
        $patterns = is_array($tells) ? (array) ($tells['patterns'] ?? []) : [];
        if ($literals === [] && $patterns === []) {
            throw new RuntimeException(
                'WAF-lookalike tell list is empty or malformed — refusing to build a no-op guard that '
                . 'would pass every response as clean.'
            );
        }

        return new self($literals, $patterns);
    }

    /**
     * Every WAF-lookalike tell found in $text.
     *
     * @return string[] the offending tells (empty ⇒ clean)
     */
    public function scan(string $text): array
    {
        $hits = [];
        foreach ($this->literals as $needle) {
            if (stripos($text, $needle) !== false) {
                $hits[] = $needle;
            }
        }
        foreach ($this->patterns as $pattern) {
            if (@preg_match('~' . $pattern . '~i', $text) === 1) {
                $hits[] = '/' . $pattern . '/';
            }
        }

        return $hits;
    }
}
