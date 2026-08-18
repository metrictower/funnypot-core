<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Derives a template's product/stack identity (`pid`) — the persona axis the merge
 * splits bundles on (§5), so one synthesized response never claims two products at once.
 *
 * `info.metadata.product` is authoritative when present (~half the corpus). Otherwise we
 * fall back to the first tag that names a product rather than a generic category. When
 * nothing product-like is found the pid is empty, which the merge treats as "no identity"
 * — compatible with any bundle (it adds no second product), never forcing a merge.
 */
final class ProductIdentity
{
    /** Tags that describe a category/severity/technique, not a product. */
    private const GENERIC = [
        'cve', 'cves', 'kev', 'edb', 'packetstorm', 'seclists', 'oss',
        'tech', 'detect', 'detection', 'exposure', 'exposures', 'config', 'misconfig',
        'misconfiguration', 'panel', 'login', 'default-login', 'unauth', 'auth-bypass',
        'vuln', 'vulnerability', 'rce', 'lfi', 'rfi', 'sqli', 'xss', 'ssrf', 'ssti',
        'redirect', 'open-redirect', 'disclosure', 'info', 'injection', 'intrusive',
        'fuzz', 'fuzzing', 'generic', 'network', 'file', 'dns', 'headless', 'osint',
        'token', 'tokens', 'backup', 'listing', 'files', 'creds', 'credential',
        'credentials', 'takeover', 'subdomain-takeover', 'honeypot', 'iot', 'misc',
        'traversal', 'lfi-detect', 'debug', 'logs', 'log', 'status', 'error',
        'top-100', 'top-200', 'wp-plugin', 'wp-theme', 'plugin', 'theme',
        'cnvd', 'huntr', 'xxe', 'deserialization', 'idor', 'crlf', 'cors',
        'auth', 'unauthenticated', 'admin', 'install', 'setup', 'sensitive',
    ];

    public static function of(string $product, array $tags): string
    {
        if ($product !== '') {
            return self::slug($product);
        }

        foreach ($tags as $tag) {
            $slug = self::slug((string) $tag);
            if ($slug === '' || in_array($slug, self::GENERIC, true)) {
                continue;
            }

            return $slug;
        }

        return '';
    }

    private static function slug(string $s): string
    {
        $s = strtolower(trim($s));
        $s = preg_replace('/[^a-z0-9]+/', '-', $s) ?? '';

        return trim($s, '-');
    }
}
