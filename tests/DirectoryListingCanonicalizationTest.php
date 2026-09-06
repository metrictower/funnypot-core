<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use DOMDocument;
use Funnypot\Core\Compiler\RouteBundleSynth;
use Funnypot\Core\Compiler\RouteIndexFold;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0196: the two authored directory listings (/.aws/, /typo3conf/) serve their autoindex only at
 * the trailing-slash base; the no-slash base answers a DirectorySlash 301 to the slash form so the
 * listing's relative child links stay base-independent. This pins the full redirect wire contract,
 * proves every listed relative child still resolves through the real engine, and proves the
 * synchronizing fold swaps the stale no-slash listing bundle for the redirect bundle.
 */
final class DirectoryListingCanonicalizationTest extends TestCase
{
    /** The two no-slash bases and the slash target each canonicalizes to. */
    private const CASES = [
        '/.aws' => '/.aws/',
        '/typo3conf' => '/typo3conf/',
    ];

    private function engine(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'fixed'; },
            'coherent',
            'realistic',
            'high',
            65536,
            0,
            0,
            true
        );

        return new Honeypot($store, $config);
    }

    /**
     * The exact Apache/IETF HTML-2.0 redirect body TemplateAttackEmulator::canonicalSlashRedirect()
     * produces for a slash target — authored verbatim in the redirect templates.
     */
    private static function redirectBody(string $target): string
    {
        return "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            . "<html><head>\n<title>301 Moved Permanently</title>\n</head><body>\n"
            . "<h1>Moved Permanently</h1>\n"
            . "<p>The document has moved <a href=\"{$target}\">here</a>.</p>\n"
            . "</body></html>\n";
    }

    public function test_get_head_and_post_canonicalize_no_slash_to_slash(): void
    {
        $eng = $this->engine();
        // The resolver deliberately falls HEAD and POST back to the GET bundle, so all three get the
        // same modeled redirect; every other verb has no redirect bundle (asserted separately).
        foreach (self::CASES as $noSlash => $slash) {
            foreach (['GET', 'HEAD', 'POST'] as $method) {
                $r = $eng->respond(new RequestContext($method, $noSlash));
                self::assertNotNull($r, "{$method} {$noSlash} must serve a redirect");
                self::assertSame(301, $r->status, "{$method} {$noSlash} status");
                self::assertSame($slash, $r->headers['Location'] ?? null, "{$method} {$noSlash} Location");
                self::assertSame('text/html; charset=iso-8859-1', $r->headers['Content-Type'] ?? null, "{$method} {$noSlash} Content-Type");
                self::assertSame(self::redirectBody($slash), $r->body, "{$method} {$noSlash} body is the exact canonical-slash shape, no taunt");
                self::assertStringNotContainsString('<!--', $r->body, "{$method} {$noSlash} carries no taunt block");
            }
        }
    }

    public function test_other_verbs_have_no_redirect_bundle(): void
    {
        $eng = $this->engine();
        foreach (array_keys(self::CASES) as $noSlash) {
            // No redirect bundle exists for these verbs: PUT/PATCH/DELETE resolve exact-only (null),
            // OPTIONS/TRACE get the bounded method-coverage answer — never a 301/Location.
            foreach (['PUT', 'PATCH', 'DELETE'] as $method) {
                self::assertNull($eng->respond(new RequestContext($method, $noSlash)), "{$method} {$noSlash} must be unmatched");
            }
            foreach (['OPTIONS', 'TRACE'] as $method) {
                $r = $eng->respond(new RequestContext($method, $noSlash));
                if ($r !== null) {
                    self::assertNotSame(301, $r->status, "{$method} {$noSlash} must not redirect");
                    self::assertArrayNotHasKey('Location', $r->headers, "{$method} {$noSlash} must not carry a Location");
                }
            }
        }
    }

    public function test_no_query_host_or_scheme_is_reflected(): void
    {
        $eng = $this->engine();
        foreach (self::CASES as $noSlash => $slash) {
            $r = $eng->respond(new RequestContext(
                'GET',
                $noSlash,
                'redir=https://evil.example/%2f..&x=../../etc/passwd',
                ['Host' => 'evil.example'],
                null,
                'evil.example',
                'http'
            ));
            self::assertNotNull($r, "{$noSlash} must still redirect under hostile input");
            self::assertSame(301, $r->status, "{$noSlash} status under hostile input");
            // Location is the static rooted-relative target — no open redirect, no reflected authority.
            self::assertSame($slash, $r->headers['Location'] ?? null, "{$noSlash} Location must be the static slash target");
            foreach (['evil.example', 'passwd', 'redir=', 'http://'] as $sentinel) {
                self::assertStringNotContainsString($sentinel, (string) ($r->headers['Location'] ?? ''), "{$noSlash} Location leaks {$sentinel}");
                self::assertStringNotContainsString($sentinel, $r->body, "{$noSlash} body leaks {$sentinel}");
            }
        }
    }

    public function test_slash_listings_are_unchanged_200_autoindexes(): void
    {
        $eng = $this->engine();
        $slashCases = [
            '/.aws/' => 'Index of /.aws',
            '/typo3conf/' => 'Index of /typo3conf',
        ];
        foreach ($slashCases as $slash => $marker) {
            $r = $eng->respond(new RequestContext('GET', $slash));
            self::assertNotNull($r, "{$slash} must serve the listing");
            self::assertSame(200, $r->status, "{$slash} status");
            self::assertSame('text/html; charset=utf-8', $r->headers['Content-Type'] ?? null, "{$slash} Content-Type");
            self::assertStringContainsString($marker, $r->body, "{$slash} must carry its autoindex marker");
            // The slash target must never itself match a redirect — no loop.
            self::assertArrayNotHasKey('Location', $r->headers, "{$slash} must not redirect (no loop)");
        }
    }

    public function test_every_listed_relative_child_resolves_through_the_engine(): void
    {
        $eng = $this->engine();
        foreach (self::CASES as $noSlash => $slash) {
            $listing = $eng->respond(new RequestContext('GET', $slash));
            self::assertNotNull($listing, "{$slash} must serve the listing");

            $children = self::relativeChildHrefs($listing->body);
            self::assertNotEmpty($children, "{$slash} listing must advertise at least one relative child");

            foreach ($children as $href) {
                // A browser resolves a relative href against the slash base; the same href off the
                // no-slash base would resolve one level up. Prove the slash-base resolution is served.
                $childPath = $slash . $href;
                $child = $eng->respond(new RequestContext('GET', $childPath));
                self::assertNotNull($child, "listed child {$childPath} must resolve to a served fake, not dangle");
                self::assertSame(200, $child->status, "listed child {$childPath} status");
            }
        }
    }

    /**
     * The relative file hrefs of an autoindex body, HTML-parsed (not string-scraped): drops the
     * column-sort query links (?C=…), the parent link (../) and any rooted-absolute href.
     *
     * @return string[]
     */
    private static function relativeChildHrefs(string $html): array
    {
        $dom = new DOMDocument();
        $prev = libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_use_internal_errors($prev);

        $out = [];
        foreach ($dom->getElementsByTagName('a') as $a) {
            $href = $a->getAttribute('href');
            if ($href === '' || $href[0] === '/' || $href[0] === '?' || $href[0] === '#') {
                continue;
            }
            if ($href === '../' || strpos($href, '..') === 0) {
                continue;
            }
            $out[] = $href;
        }

        return array_values(array_unique($out));
    }

    public function test_fold_swaps_the_stale_no_slash_listing_bundle_for_the_redirect(): void
    {
        // A pre-FP-0196 index: both no-slash and slash bases carried the SAME listing bundle.
        $staleIndex = [
            'schema' => 1,
            'templates' => [
                'route-dotaws-listing' => ['name' => 'aws listing'],
                'route-typo3conf-listing' => ['name' => 'typo3 listing'],
            ],
            'routes' => [
                'GET /.aws' => ['b' => [['pid' => 'route-dotaws-listing', 's' => 200, 't' => ['route-dotaws-listing']]]],
                'GET /.aws/' => ['b' => [['pid' => 'route-dotaws-listing', 's' => 200, 't' => ['route-dotaws-listing']]]],
                'GET /typo3conf' => ['b' => [['pid' => 'route-typo3conf-listing', 's' => 200, 't' => ['route-typo3conf-listing']]]],
                'GET /typo3conf/' => ['b' => [['pid' => 'route-typo3conf-listing', 's' => 200, 't' => ['route-typo3conf-listing']]]],
            ],
        ];

        // The real current fragment authored by templates/route.
        $fragment = (new RouteBundleSynth())->fragment(__DIR__ . '/../templates/route');
        $folded = (new RouteIndexFold())->apply($staleIndex, $fragment)['index'];

        $pidsAt = static function (array $index, string $key): array {
            $pids = [];
            foreach ((array) ($index['routes'][$key]['b'] ?? []) as $b) {
                $pids[] = $b['pid'];
            }

            return $pids;
        };

        // No-slash keys now carry ONLY the redirect PID; the stale listing bundle is gone.
        self::assertSame(['route-dotaws-canonical-slash'], $pidsAt($folded, 'GET /.aws'));
        self::assertSame(['route-typo3conf-canonical-slash'], $pidsAt($folded, 'GET /typo3conf'));
        // Slash keys still carry ONLY the listing PID.
        self::assertSame(['route-dotaws-listing'], $pidsAt($folded, 'GET /.aws/'));
        self::assertSame(['route-typo3conf-listing'], $pidsAt($folded, 'GET /typo3conf/'));
    }
}
