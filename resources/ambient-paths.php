<?php

declare(strict_types=1);

/**
 * Paths a site is asked for whether or not it has them — browsers, mobile platforms, password
 * managers and standards-following crawlers fetch these UNPROMPTED, so a 404 for one is not
 * evidence of anything. They are in the nuclei corpus because scanners request them too, which
 * is exactly why a bare corpus match cannot be the report signal.
 *
 * Both halves of the build read this list (Compiler\AmbientPaths): the corpus compiler stamps
 * amb=1 on every bundle at a listed GET key, and the new-page fragment synth stamps amb=1 on a
 * folded decoy bundle at a listed key. There is no per-template override.
 *
 * Rules for this list, and they matter:
 *
 *  - EXACT, root-anchored paths only. Never a prefix or substring rule: the corpus contains
 *    /actuator/favicon.ico and /web/manifest.json, and both are genuine probes.
 *  - GET only. Every path here is something a browser/crawler fetches with GET; the build keys
 *    this list under GET only (Compiler\AmbientPaths::routeKeys()).
 *  - Unprompted only. If a page has to link it, the request carries a Referer and the path
 *    exists, so it never reaches here.
 *  - Append-only, hand-curated. The whole value of the approach is that it stays this small.
 *  - An edit here needs `composer build-corpus`, not just `composer build`: the corpus half is
 *    only restamped by a full rebuild (docs/CORPUS-PIPELINE.md).
 *
 * Deliberately excluded: /.well-known/openid-configuration (no browser fetches it unprompted,
 * and it is a real recon target) and /crossdomain.xml (same).
 *
 * Not every path here is a route key in the compiled corpus — a path with no matching template
 * (e.g. /humans.txt) has nothing to stamp and classifies CLEAN. That is expected: this is the
 * full, forward-looking set, so a path that gains a template later is covered with no list change.
 */
return [
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
    '/sitemap_index.xml',
    '/manifest.json',
    '/site.webmanifest',
    '/browserconfig.xml',
    '/apple-touch-icon.png',
    '/apple-touch-icon-precomposed.png',
    '/humans.txt',
    '/ads.txt',
    '/app-ads.txt',
    '/.well-known/security.txt',
    '/.well-known/change-password',
    '/.well-known/apple-app-site-association',
    '/.well-known/assetlinks.json',
    '/.well-known/dnt-policy.txt',
];
