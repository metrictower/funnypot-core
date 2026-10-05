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
 * PATH DISCIPLINE (FP-0357 review Finding 1): every CONTENT-bearing sample sits on a NEUTRAL store-miss
 * path (`/shop/<unique>`), so its bare path classifies CLEAN and the benign CONTENT (query/body/header) is
 * the sole thing measured. Parking content on a corpus-key path (bare `/search` is itself a decoy) would
 * let the differential mask the content's true FP behaviour. The only non-`/shop/` entries are the common
 * AMBIENT browser paths (robots/favicon/sitemap/…), which carry no params and prove normal traffic is not
 * a false positive (AMBIENT is excluded from the FP set — see FalsePositiveReportTest / Verdict.php).
 *
 * Shape: list of ['label','method','path','query','headers','body'] (body → RequestContext $rawBody).
 * Host is a fixed 'shop.example.test' so same-host redirect samples are unambiguous. Labels prefixed
 * `fp0582:` / `fpcrs:` DELIBERATELY trip an accepted/known CRS false positive so the report quantifies it.
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
    // --- common AMBIENT browser paths (no params; must NOT be a false positive) ---
    $g('ambient:robots', '/robots.txt'),
    $g('ambient:favicon', '/favicon.ico'),
    $g('ambient:sitemap', '/sitemap.xml'),
    $g('ambient:apple-touch', '/apple-touch-icon.png'),
    $g('ambient:security-txt', '/.well-known/security.txt'),

    // --- prose containing SQL / shell words (benign free text) ---
    $g('prose:union-drop', '/shop/search-prose-1', 'q=' . rawurlencode('best union jack flag and a drop-shipping deal')),
    $g('prose:select-order', '/shop/feedback', 'msg=' . rawurlencode("I'll select the standard plan or maybe the pro one")),
    $g('prose:where-meadows', '/shop/search-prose-2', 'q=' . rawurlencode('cottages near Where Meadows, select views')),
    $g('prose:update-insert', '/shop/notes', 'text=' . rawurlencode('please update my address and insert the new one')),

    // --- phone numbers ---
    $g('phone:us', '/shop/contact-us', 'phone=' . rawurlencode('1-800-555-0137')),
    $g('phone:intl', '/shop/contact-intl', 'tel=' . rawurlencode('+44 20 7946 0958')),

    // --- product titles / SKUs (digits, dashes, parens) ---
    $g('product:or7', '/shop/catalog-1', 'q=' . rawurlencode('OR-7 Monitor Arm (adjustable)')),
    $g('product:sku', '/shop/catalog-2', 'sku=' . rawurlencode('AND-1024-X')),
    $g('product:select-size', '/shop/catalog-3', 'q=' . rawurlencode('Select-A-Size Paper Towels, 6 pack')),

    // --- legitimate base64 tokens (cookie / CSRF / opaque id) ---
    $g('base64:cookie', '/shop/account-1', '', ['Cookie' => 'sid=dXNlcjoxMjM0NTY3ODkwYWJjZGVm']),
    $g('base64:query', '/shop/share', 'ref=' . rawurlencode('ZXhhbXBsZS1zaGFyZS1yZWZlcmVuY2U=')),

    // --- i18n / unicode ---
    $g('i18n:name', '/shop/register', 'name=' . rawurlencode('José Müller')),
    $g('i18n:prose', '/shop/search-i18n', 'q=' . rawurlencode('naïve café crème brûlée recipe')),
    $g('i18n:city', '/shop/shipping', 'city=' . rawurlencode('São Paulo')),

    // --- JSON API bodies (attack-ish tokens inside legitimate JSON) ---
    $p('json:order-filter', '/shop/api-orders', '{"filter":"status=active","sort":"-created_at","q":"union catalog"}'),
    // NOTE: a plain product search whose value contains the word "select" — see fpcrs: below; parked on a
    // neutral path so its content is actually measured (review Finding 1).
    $p('fpcrs:json-select', '/shop/api-search', '{"query":"select 2024 laptop models","page":2,"perPage":20}'),

    // --- ordinary querystrings ---
    $g('query:paging', '/shop/products-list', 'page=2&sort=price&category=electronics'),
    $g('query:range', '/shop/search-range', 'q=laptop&min=500&max=1500&inStock=true'),

    // --- dotted / dashed paths (attack-ish path shape; carried as a query so content is measured) ---
    $g('path:item', '/shop/catalog-item', 'id=' . rawurlencode('item-3-2')),
    $g('path:dated-post', '/shop/blog', 'slug=' . rawurlencode('2024-01-15-release-notes')),
    $g('path:versioned-file', '/shop/files', 'name=' . rawurlencode('report-v1.2.3.pdf')),

    // --- versions / dates ---
    $g('version:semver', '/shop/api-status', 'v=1.2.3&since=2024-06-01'),

    // --- math-looking values ---
    $g('math:ratio', '/shop/render', 'aspect=' . rawurlencode('16/9')),
    $g('math:discount', '/shop/cart-note', 'note=' . rawurlencode('10-2 off this week')),

    // --- relative redirect (benign; no // host) + absolute same-host redirect ---
    $g('redirect:relative', '/shop/login-return', 'next=' . rawurlencode('/account/settings')),
    $g('redirect:absolute-samehost', '/shop/go-back', 'redirect_uri=' . rawurlencode('https://shop.example.test/dashboard')),

    // --- benign file names (no traversal / wrapper) ---
    $g('file:download', '/shop/download', 'file=' . rawurlencode('quarterly-report.pdf')),
    $g('file:asset', '/shop/assets', 'path=' . rawurlencode('css/main.min.css')),

    // --- accept-language header that mentions locales but is benign ---
    $g('header:lang', '/shop/home', '', ['Accept-Language' => 'en-GB,en;q=0.9,fr;q=0.8']),

    // --- more ordinary traffic (boolean prose, API field-select, graphql, jwt cookie, map bbox) ---
    $g('prose:and-or', '/shop/search-bool', 'q=' . rawurlencode('cats and dogs or small birds')),
    $g('api:field-select', '/shop/api-users', 'select=name,email&order=name'),
    $p('json:graphql', '/shop/graphql-api', '{"query":"{ viewer { id name orders(first:10){ total } } }"}'),
    $g('cookie:jwt', '/shop/account-2', '', ['Cookie' => 'auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJl']),
    $g('map:bbox', '/shop/map', 'bbox=' . rawurlencode('1.23,4.56,7.89,0.12') . '&zoom=11'),

    // === DELIBERATE FP-0582 accepted false positives (quantified in the report), neutral paths ===
    $g('fp0582:information_schema', '/shop/help-articles', 'q=' . rawurlencode('the information_schema tutorial explained views well')),
    $g('fp0582:fpd-array', '/shop/catalog-filter', 'tags[]=books&tags[]=sale'),
    $g('fp0582:verbose-error-hex', '/shop/report-view', 'page=0x1F'),
    $g('fp0582:crs-rce-ipconfig', '/shop/net-tools', 'host=router&ipconfig=auto'),
];
