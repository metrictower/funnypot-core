<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\EmulatorRegistry;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * FP-0316 — the path-aware directory-listing graph.
 *
 * Every one of the 15 formerly-generic listing keys must render its OWN correct listing (right title,
 * product entries, detector tokens woven into the document) and every advertised link must resolve —
 * after RFC relative-path resolution — to a served inert response (a 200 lure, a deliberate 403 parent,
 * or the site root homepage), never a null/404/5xx dangling link. The old one-size "Index of /backup"
 * body is gone: no page claims /backup unless it is /backup/, and the retired generic filenames do not
 * leak. Rendered through the real ResponseSynthesizer so hw/rx witnesses are exercised end-to-end.
 */
final class DirectoryListingGraphTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index = null;

    /**
     * dataset name => [route key, directory-listing bundle index, expected canonical title path]. The
     * root's listing bundle is #21 (a Tomcat autoindex among the 41 root bundles); every other key
     * carries exactly one directory-listing bundle at index 0.
     *
     * @return array<string,array{0:string,1:int,2:string}>
     */
    public static function listings(): array
    {
        return [
            'GET /' => ['GET /', 21, '/'],
            'GET /App_Data/' => ['GET /App_Data/', 0, '/App_Data'],
            'GET /App_Plugins/' => ['GET /App_Plugins/', 0, '/App_Plugins'],
            'GET /backup/' => ['GET /backup/', 0, '/backup'],
            'GET /files/_sessions/' => ['GET /files/_sessions/', 0, '/files/_sessions'],
            'GET /glpi/' => ['GET /glpi/', 0, '/glpi'],
            'GET /glpi/files/' => ['GET /glpi/files/', 0, '/glpi/files'],
            'GET /glpi/files/_sessions/' => ['GET /glpi/files/_sessions/', 0, '/glpi/files/_sessions'],
            'GET /irj/go/km/navigation/' => ['GET /irj/go/km/navigation/', 0, '/irj/go/km/navigation'],
            'GET /log/' => ['GET /log/', 0, '/log'],
            'GET /php/backup/' => ['GET /php/backup/', 0, '/php/backup'],
            'GET /wp-content/plugins/' => ['GET /wp-content/plugins/', 0, '/wp-content/plugins'],
            'GET /wp-content/themes/' => ['GET /wp-content/themes/', 0, '/wp-content/themes'],
            'GET /wp-content/uploads/' => ['GET /wp-content/uploads/', 0, '/wp-content/uploads'],
            'GET /wp-includes/' => ['GET /wp-includes/', 0, '/wp-includes'],
        ];
    }

    /** The three 403 parents that no corpus route serves — the ../ targets FP-0316 wires forbidden. */
    private const FORBIDDEN_PARENTS = ['/irj/go/km/', '/php/', '/wp-content/'];

    /** The retired generic listing's filenames — must not leak except where explicitly re-listed. */
    private const RETIRED_NAMES = ['database.sql', 'www.tar.gz'];

    /** @return array<string,mixed> */
    private static function index(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }

    private function synth(int $seed): ResponseSynthesizer
    {
        return new ResponseSynthesizer(EmulatorRegistry::default($seed), Style::REALISTIC, null, null, $seed);
    }

    private function tauntSynth(int $seed): ResponseSynthesizer
    {
        return new ResponseSynthesizer(EmulatorRegistry::default($seed), Style::TAUNT, null, null, $seed);
    }

    private function inverter(): Honeypot
    {
        $store = new PhpArrayStore(self::index());

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'graph-seed'; },
            'coherent',
            'realistic'
        ));
    }

    /** @return array<string,mixed> */
    private function bundle(string $key, int $i): array
    {
        $routes = self::index()['routes'] ?? [];
        self::assertArrayHasKey($key, $routes, "route {$key} is not in the compiled index");

        return $routes[$key]['b'][$i];
    }

    /**
     * Resolve an href against a directory base (RFC 3986 path semantics). Returns null for a same-page
     * query/fragment link (sort controls), which never navigates away.
     */
    private function resolve(string $baseDir, string $href): ?string
    {
        if ($href === '' || $href[0] === '?' || $href[0] === '#') {
            return null;
        }
        $path = $href[0] === '/' ? $href : $baseDir . $href;
        $out = [];
        foreach (explode('/', $path) as $seg) {
            if ($seg === '..') {
                if ($out !== [] && end($out) !== '') {
                    array_pop($out);
                }
            } elseif ($seg !== '.') {
                $out[] = $seg;
            }
        }
        $resolved = implode('/', $out);

        return $resolved === '' ? '/' : $resolved;
    }

    /**
     * @dataProvider listings
     */
    public function test_listing_renders_its_own_path_aware_body(string $key, int $i, string $title): void
    {
        $bundle = $this->bundle($key, $i);

        foreach ([0, 1, 7, 42, 777, 123456] as $seed) {
            $resp = $this->synth($seed)->synthesize($bundle, Detection::none(), 'graph|' . $seed, $key);
            self::assertInstanceOf(SynthesizedResponse::class, $resp, "{$key} must render a rich listing (seed {$seed})");
            self::assertSame(200, $resp->status, "{$key} listing is a 200 (seed {$seed})");
            self::assertStringStartsWith('text/html', (string) ($resp->headers['Content-Type'] ?? ''), "{$key} listing is HTML (seed {$seed})");

            $body = $resp->body;
            self::assertStringContainsString('<title>Index of ' . $title . '</title>', $body, "{$key} must title itself with its own canonical path (seed {$seed})");
            self::assertStringContainsString('<h1>Index of ' . $title . '</h1>', $body, "{$key} h1 must match its canonical path (seed {$seed})");

            // Every required matcher token (bw + rx witness) is woven INTO the document — so nothing is
            // appended after </html> in REALISTIC style.
            foreach (array_merge((array) ($bundle['bw'] ?? []), (array) ($bundle['rx'] ?? [])) as $tok) {
                if ((string) $tok !== '') {
                    self::assertStringContainsString((string) $tok, $body, "{$key} must weave the matcher token [{$tok}] into the body (seed {$seed})");
                }
            }
            $tail = substr($body, strpos($body, '</html>') + 7);
            self::assertSame('', trim($tail), "{$key} REALISTIC body must end at </html> — no appended token tail (seed {$seed})");
        }
    }

    /**
     * @dataProvider listings
     */
    public function test_every_advertised_link_resolves_to_a_served_response(string $key, int $i, string $title): void
    {
        $baseDir = substr($key, 4); // strip 'GET '
        $resp = $this->synth(7)->synthesize($this->bundle($key, $i), Detection::none(), 'graph|7', $key);
        self::assertNotNull($resp);
        $inv = $this->inverter();

        self::assertGreaterThan(0, preg_match_all('/href="([^"]*)"/', $resp->body, $m), "{$key} must advertise links");
        $checked = 0;
        foreach (array_unique($m[1]) as $href) {
            $dest = $this->resolve($baseDir, $href);
            if ($dest === null) {
                continue; // sort-control query link — same page
            }
            $checked++;

            if ($dest === '/') {
                // The Parent Directory of a top-level listing is the site root — the homepage, a real
                // served surface classified `clean` (never a honeypot 404). Same idiom as FP-0196.
                $verdict = $inv->classify(new RequestContext('GET', '/'), SiteProfile::empty());
                self::assertNotNull($verdict, "{$key}: root parent must classify to a real surface");
                continue;
            }

            $dr = $inv->respond(new RequestContext('GET', $dest));
            self::assertNotNull($dr, "{$key}: advertised link {$href} -> {$dest} must resolve to a served response, not a 404 (dangling)");
            self::assertLessThan(500, $dr->status, "{$key}: {$dest} must never be a 5xx");
            self::assertNotSame(404, $dr->status, "{$key}: {$dest} must not be a synthetic 404");
            self::assertNotSame('', (string) ($dr->headers['Content-Type'] ?? ''), "{$key}: {$dest} must carry a Content-Type");

            if (in_array($dest, self::FORBIDDEN_PARENTS, true)) {
                self::assertSame(403, $dr->status, "{$key}: the forbidden parent {$dest} must be a deliberate 403");
            } else {
                self::assertSame(200, $dr->status, "{$key}: the lure {$dest} must be a 200");
            }
        }
        self::assertGreaterThan(0, $checked, "{$key} must advertise at least one resolvable link");
    }

    public function test_no_page_claims_backup_unless_it_is_backup(): void
    {
        // The retired defect: one hard-coded "Index of /backup" served across unrelated keys.
        foreach (self::listings() as [$key, $i, $title]) {
            $body = $this->synth(3)->synthesize($this->bundle($key, $i), Detection::none(), 'graph|3', $key)->body;
            $claimsBackup = strpos($body, 'Index of /backup') !== false;
            if ($key === 'GET /backup/') {
                self::assertTrue($claimsBackup, '/backup/ must claim /backup');
            } else {
                self::assertFalse($claimsBackup, "{$key} must not claim /backup (the retired generic tell)");
            }
        }
    }

    public function test_retired_generic_filenames_do_not_leak(): void
    {
        // database.sql / www.tar.gz appeared in the old generic body and belong nowhere now;
        // config.php.bak is legitimately re-listed only by the /php/backup/ listing.
        foreach (self::listings() as [$key, $i, $title]) {
            $body = $this->synth(11)->synthesize($this->bundle($key, $i), Detection::none(), 'graph|11', $key)->body;
            foreach (self::RETIRED_NAMES as $name) {
                self::assertStringNotContainsString($name, $body, "{$key} must not carry the retired generic filename {$name}");
            }
            if ($key !== 'GET /php/backup/') {
                self::assertStringNotContainsString('config.php.bak', $body, "{$key} must not carry config.php.bak (only /php/backup/ lists it)");
            }
        }
    }

    /**
     * @dataProvider listings
     */
    public function test_listing_render_is_deterministic(string $key, int $i, string $title): void
    {
        $bundle = $this->bundle($key, $i);
        $a = $this->synth(777)->synthesize($bundle, Detection::none(), 'graph|777', $key);
        $b = $this->synth(777)->synthesize($bundle, Detection::none(), 'graph|777', $key);
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, "{$key} must render byte-identically for a fixed seed");
    }

    /**
     * @dataProvider listings
     */
    public function test_taunt_style_still_serves_and_carries_the_marker(string $key, int $i, string $title): void
    {
        $bundle = $this->bundle($key, $i);
        $resp = $this->tauntSynth(7)->synthesize($bundle, Detection::none(), 'graph|taunt', $key);
        self::assertNotNull($resp, "{$key} must serve under TAUNT");
        self::assertStringContainsString('Index of ' . $title, $resp->body, "{$key} taunt body must still carry its listing (title)");
        self::assertStringContainsStringIgnoringCase('nice try', $resp->body, "{$key} taunt must carry the marker");
    }
}
