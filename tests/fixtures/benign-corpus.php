<?php

declare(strict_types=1);

/**
 * FP-0357 — a funnypot-owned, CLEAN-ROOM benign HTTP corpus for the false-positive testing report.
 *
 * Every entry is ORIGINALLY AUTHORED here. The libinjection `data/false_positives.txt` categories and
 * blazehttp `.white` set were used ONLY as a checklist of WHAT to cover (prose containing SQL/shell words,
 * phone numbers, product titles, base64, i18n/unicode, etc.) — never as lines to copy. No upstream line is
 * reproduced, and no nuclei/CRS matcher-word is reproduced verbatim even as prose (fingerprint-safety
 * invariant 1). These are requests a real visitor / a real client app would send: attack-ish-looking but
 * benign.
 *
 * Shape: list of ['label','method','path','query','headers','body'] (body → RequestContext $rawBody).
 * The host is a fixed 'shop.example.test' so same-host redirect samples are unambiguous.
 *
 * Some samples DELIBERATELY trip a known, accepted false positive (FP-0582 WON'T-FIX rules) so the report
 * quantifies them — those labels are prefixed `fp0582:`. The common AMBIENT browser paths (robots/favicon/
 * sitemap) are included to prove normal traffic is NOT a false positive (AMBIENT is excluded from the FP
 * set — see FalsePositiveReportTest / Verdict.php).
 *
 * @return array<int, array{label:string,method:string,path:string,query:string,headers:array<string,string>,body:?string}>
 */

$g = static function (string $label, string $path, string $query = '', array $headers = []): array {
    return ['label' => $label, 'method' => 'GET', 'path' => $path, 'query' => $query, 'headers' => $headers, 'body' => null];
};
$p = static function (string $label, string $path, string $body, string $ct = 'application/json'): array {
    return ['label' => $label, 'method' => 'POST', 'path' => $path, 'query' => '', 'headers' => ['Content-Type' => $ct], 'body' => $body];
};

return [
    // --- common AMBIENT browser paths (must NOT be a false positive) ---
    $g('ambient:robots', '/robots.txt'),
    $g('ambient:favicon', '/favicon.ico'),
    $g('ambient:sitemap', '/sitemap.xml'),
    $g('ambient:apple-touch', '/apple-touch-icon.png'),
    $g('ambient:security-txt', '/.well-known/security.txt'),

    // --- prose containing SQL / shell words (benign free text) ---
    $g('prose:union-drop', '/search', 'q=' . rawurlencode('best union jack flag and a drop-shipping deal')),
    $g('prose:select-order', '/feedback', 'msg=' . rawurlencode("I'll select the standard plan or maybe the pro one")),
    $g('prose:where-meadows', '/search', 'q=' . rawurlencode('cottages near Where Meadows, select views')),
    $g('prose:update-insert', '/notes', 'text=' . rawurlencode('please update my address and insert the new one')),

    // --- phone numbers ---
    $g('phone:us', '/contact', 'phone=' . rawurlencode('1-800-555-0137')),
    $g('phone:intl', '/contact', 'tel=' . rawurlencode('+44 20 7946 0958')),

    // --- product titles / SKUs (digits, dashes, parens) ---
    $g('product:or7', '/catalog', 'q=' . rawurlencode('OR-7 Monitor Arm (adjustable)')),
    $g('product:sku', '/catalog', 'sku=' . rawurlencode('AND-1024-X')),
    $g('product:select-size', '/catalog', 'q=' . rawurlencode('Select-A-Size Paper Towels, 6 pack')),

    // --- legitimate base64 tokens (cookie / CSRF / opaque id) ---
    $g('base64:cookie', '/account', '', ['Cookie' => 'sid=dXNlcjoxMjM0NTY3ODkwYWJjZGVm']),
    $g('base64:query', '/share', 'ref=' . rawurlencode('ZXhhbXBsZS1zaGFyZS1yZWZlcmVuY2U=')),

    // --- i18n / unicode ---
    $g('i18n:name', '/register', 'name=' . rawurlencode('José Müller')),
    $g('i18n:prose', '/search', 'q=' . rawurlencode('naïve café crème brûlée recipe')),
    $g('i18n:city', '/shipping', 'city=' . rawurlencode('São Paulo')),

    // --- JSON API bodies (attack-ish tokens inside legitimate JSON) ---
    $p('json:order-filter', '/api/orders', '{"filter":"status=active","sort":"-created_at","q":"union catalog"}'),
    $p('json:search', '/api/search', '{"query":"select 2024 laptop models","page":2,"perPage":20}'),

    // --- ordinary querystrings ---
    $g('query:paging', '/products', 'page=2&sort=price&category=electronics'),
    $g('query:range', '/search', 'q=laptop&min=500&max=1500&inStock=true'),

    // --- dotted / dashed paths (no traversal) ---
    $g('path:item', '/products/item-3-2'),
    $g('path:dated-post', '/blog/2024-01-15-release-notes'),
    $g('path:versioned-file', '/files/report-v1.2.3.pdf'),

    // --- versions / dates ---
    $g('version:semver', '/api/status', 'v=1.2.3&since=2024-06-01'),

    // --- math-looking values ---
    $g('math:ratio', '/render', 'aspect=' . rawurlencode('16/9')),
    $g('math:discount', '/cart', 'note=' . rawurlencode('10-2 off this week')),

    // --- relative redirect (benign; no // host, so NOT an open-redirect) ---
    $g('redirect:relative', '/login', 'next=' . rawurlencode('/account/settings')),

    // --- benign file names (no traversal / wrapper) ---
    $g('file:download', '/download', 'file=' . rawurlencode('quarterly-report.pdf')),
    $g('file:asset', '/assets/css/main.min.css'),

    // --- accept-language / UA that mention bots but are benign ---
    $g('header:lang', '/', '', ['Accept-Language' => 'en-GB,en;q=0.9,fr;q=0.8']),

    // --- more ordinary traffic (boolean prose, API field-select, graphql, jwt cookie, map bbox) ---
    $g('prose:and-or', '/search', 'q=' . rawurlencode('cats and dogs or small birds')),
    $g('api:field-select', '/api/v2/users', 'select=name,email&order=name'),
    $p('json:graphql', '/graphql', '{"query":"{ viewer { id name orders(first:10){ total } } }"}'),
    $g('cookie:jwt', '/account', '', ['Cookie' => 'auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJl']),
    $g('map:bbox', '/map', 'bbox=' . rawurlencode('1.23,4.56,7.89,0.12') . '&zoom=11'),

    // === DELIBERATE FP-0582 accepted false positives (quantified in the report) ===
    // On neutral store-miss paths so the PARAM is the sole cause (the differential harness subtracts any
    // path-driven decoy). These are the FP-0582 WON'T-FIX rules; the report documents them by name.
    $g('fp0582:information_schema', '/shop/help-articles', 'q=' . rawurlencode('the information_schema tutorial explained views well')),
    $g('redirect:absolute-samehost', '/shop/go-back', 'redirect_uri=' . rawurlencode('https://shop.example.test/dashboard')),
    $g('fp0582:fpd-array', '/shop/catalog-filter', 'tags[]=books&tags[]=sale'),
    $g('fp0582:verbose-error-hex', '/shop/report-view', 'page=0x1F'),
    $g('fp0582:crs-rce-ipconfig', '/shop/net-tools', 'host=router&ipconfig=auto'),
];
