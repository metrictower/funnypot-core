<?php

declare(strict_types=1);

namespace Funnypot\Response;

/**
 * Hand-crafted rich fake for a specific endpoint family (a believable .git/config,
 * .env, xmlrpc.php, wp-login page, …) — the "greater than nuclei" depth layer.
 *
 * An emulator only enriches a bundle the compiled index already routes to; it never
 * invents new routes, and its output is validated against the bundle's required/
 * forbidden tokens before use, with a minimal fallback if it doesn't fit. So richness
 * is free: it can only ever add believability on top of a response that already
 * satisfies the scanner.
 */
interface EndpointEmulator
{
    /**
     * True when this emulator recognises the served bundle (by template id or product).
     *
     * @param array<string,mixed> $bundle
     */
    public function supports(array $bundle): bool;

    /**
     * Render rich content for the given style. MUST embed every required body word and
     * avoid every forbidden substring (the composer re-checks). Return null to decline
     * (composer falls back to minimal synthesis).
     *
     * @param array<string,mixed> $bundle
     * @param string              $style  Style::REALISTIC | Style::TAUNT
     * @param int                 $seed   deterministic per attacker+path — vary fake
     *                                    values with it so re-scans stay byte-identical
     */
    public function render(array $bundle, string $style, int $seed): ?EmulatedContent;
}
