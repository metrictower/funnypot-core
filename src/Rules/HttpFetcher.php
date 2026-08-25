<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

/**
 * Fetches a release asset by absolute URL and returns its raw bytes. A seam so tests (and a
 * custom-TLS deployment) can supply their own transport without a network. Implementations
 * MUST enforce the anti-SSRF rules the updater relies on: HTTPS only, an allow-listed host,
 * and no redirect to an off-allowlist host.
 *
 * @throws RulesUpdateException on any transport failure
 */
interface HttpFetcher
{
    public function get(string $url): string;
}
