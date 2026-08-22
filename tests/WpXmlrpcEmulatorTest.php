<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Response\Style;
use Funnypot\SiteProfile;
use Funnypot\Store\PhpArrayStore;
use Funnypot\Template\TemplateAttackEmulator;
use Funnypot\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware WordPress xmlrpc.php emulator pack (attack rules 26/27). Drives the compiled
 * attack rules against a live RequestContext, so it pins the two-rule dispatch mechanism and the
 * load-bearing safety invariants (a credential oracle that never authenticates, a zero-egress
 * pingback, only-upgrade-a-404).
 *
 * NOTE ON PATHS: every request-aware case here uses a PREFIXED path (/wp/xmlrpc.php, …). The bare
 * /xmlrpc.php is an exact-store corpus key that classify() answers before the attack tier is ever
 * reached, so a test on bare /xmlrpc.php would exercise the store (route tier), not these rules.
 */
final class WpXmlrpcEmulatorTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** Drive one request through the compiled rules. */
    private function serve(string $method, string $path, string $query = '', ?string $body = null): ?object
    {
        return $this->emulator()->emulate(new RequestContext($method, $path, $query, [], $body));
    }

    /** Assert a served body parses as well-formed XML. */
    private function assertWellFormedXml(string $xml, string $why): void
    {
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($xml);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        self::assertNotFalse($doc, $why . ' must be well-formed XML');
    }

    // --- compile / ordering -----------------------------------------------------------------

    public function test_both_rules_compiled_unique_and_ordered(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);

        self::assertContains('attack-wp-xmlrpc', $ids);
        self::assertContains('attack-wp-xmlrpc-get', $ids);
        self::assertSame(array_unique($ids), $ids, 'template ids must be globally unique');

        // Rule 1 (POST dispatch) must sort strictly before Rule 2 (GET/fallback) so a methodCall
        // is dispatched, never swallowed by the fallback.
        self::assertLessThan(
            array_search('attack-wp-xmlrpc-get', $ids, true),
            array_search('attack-wp-xmlrpc', $ids, true)
        );
    }

    // --- GET / bodyless (rule 27) -----------------------------------------------------------

    public function test_get_returns_405_post_only(): void
    {
        $r = $this->serve('GET', '/wp/xmlrpc.php');
        self::assertNotNull($r);
        self::assertSame(405, $r->status);
        self::assertSame('text/plain; charset=UTF-8', $r->headers['Content-Type']);
        self::assertSame('POST', $r->headers['Allow']);
        // Byte-exact: the real WP die() output has NO trailing newline.
        self::assertSame('XML-RPC server accepts POST requests only.', $r->body);
        self::assertSame(['attack-wp-xmlrpc-get'], $r->satisfies->templateIds());
    }

    public function test_rsd_document(): void
    {
        $r = $this->serve('GET', '/wp/xmlrpc.php', 'rsd');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('text/xml; charset=UTF-8', $r->headers['Content-Type']);
        $this->assertWellFormedXml($r->body, 'RSD');
        self::assertStringContainsString('<rsd', $r->body);
        self::assertStringContainsString('WordPress', $r->body);
        self::assertStringContainsString('/xmlrpc.php', $r->body);
        // The persona domain must have rendered (no literal directive left behind).
        self::assertStringNotContainsString('{{', $r->body);
    }

    // --- POST method dispatch (rule 26) -----------------------------------------------------

    public function test_list_methods(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>system.listMethods</methodName></methodCall>');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('text/xml; charset=UTF-8', $r->headers['Content-Type']);
        $this->assertWellFormedXml($r->body, 'listMethods');
        self::assertStringContainsString('<methodResponse>', $r->body);
        foreach (['system.multicall', 'system.listMethods', 'pingback.ping', 'wp.getUsersBlogs'] as $m) {
            self::assertStringContainsString($m, $r->body);
        }
        self::assertSame(['attack-wp-xmlrpc'], $r->satisfies->templateIds());
    }

    public function test_get_capabilities(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>system.getCapabilities</methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'getCapabilities');
        self::assertStringContainsString('faults_interop', $r->body);
        self::assertStringContainsString('specVersion', $r->body);
    }

    public function test_say_hello(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>demo.sayHello</methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'sayHello');
        self::assertStringContainsString('<string>Hello!</string>', $r->body);
    }

    // --- credential-brute ORACLE: never authenticates ---------------------------------------

    public function test_getUsersBlogs_is_a_bad_credentials_oracle(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>bob</value></param><param><value>hunter2</value></param></params></methodCall>');
        self::assertNotNull($r);
        self::assertSame(200, $r->status); // XML-RPC fault is HTTP 200 with the code inside.
        $this->assertWellFormedXml($r->body, 'oracle fault');
        self::assertStringContainsString('<int>403</int>', $r->body);
        self::assertStringContainsString('Incorrect username or password.', $r->body);

        // SAFETY: there is NO authenticated/success branch. A real getUsersBlogs success returns an
        // <array> of blog structs (blogName/url/isAdmin); none of that may ever appear.
        self::assertStringNotContainsString('<array>', $r->body);
        self::assertDoesNotMatchRegularExpression('/isAdmin|blogName|xmlrpc_url|blogid/i', $r->body);
    }

    /** Every wp./mt./metaWeblog./blogger. auth method resolves to the same bad-credentials fault. */
    public function test_whole_auth_family_hits_the_oracle(): void
    {
        $methods = [
            'blogger.getUsersBlogs', 'metaWeblog.getUsersBlogs', 'wp.getOptions',
            'wp.getProfile', 'mt.getRecentPostTitles', 'wp.getUsers', 'wp.uploadFile',
        ];
        foreach ($methods as $m) {
            $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>' . $m . '</methodName></methodCall>');
            self::assertNotNull($r, $m);
            self::assertStringContainsString('<int>403</int>', $r->body, $m);
            self::assertStringContainsString('Incorrect username or password.', $r->body, $m);
            self::assertStringNotContainsString('<array>', $r->body, $m . ' must never grant a blog list');
        }
    }

    public function test_multicall_stopgap_is_a_bounded_fault_array(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>system.multicall</methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'multicall');
        // Fixed single-entry array carrying the bad-creds fault: true fan-out is deferred (iterate).
        self::assertStringContainsString('<array>', $r->body);
        self::assertStringContainsString('<int>403</int>', $r->body);
        self::assertStringContainsString('Incorrect username or password.', $r->body);
        self::assertDoesNotMatchRegularExpression('/isAdmin|blogName|xmlrpc_url/i', $r->body);
    }

    // --- pingback.ping: ZERO egress ---------------------------------------------------------

    public function test_pingback_returns_static_fault_and_reflects_no_uri(): void
    {
        $source = 'http://169.254.169.254/latest/meta-data/';
        $target = 'http://internal.example/secret';
        $r = $this->serve(
            'POST',
            '/wp/xmlrpc.php',
            '',
            '<methodCall><methodName>pingback.ping</methodName><params>'
            . '<param><value><string>' . $source . '</string></value></param>'
            . '<param><value><string>' . $target . '</string></value></param></params></methodCall>'
        );
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'pingback fault');
        self::assertStringContainsString('<int>33</int>', $r->body);
        // Zero egress + no reflection: neither the source nor target URI may appear in the response
        // (a static template, and the URIs are never read — so nothing can trigger a fetch).
        self::assertStringNotContainsString('169.254.169.254', $r->body);
        self::assertStringNotContainsString('internal.example', $r->body);
    }

    // --- unknown method + reflection safety -------------------------------------------------

    public function test_unknown_method_reflects_the_captured_name(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>evil.doThing</methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'unknown-method fault');
        self::assertStringContainsString('<int>-32601</int>', $r->body);
        self::assertStringContainsString('requested method evil.doThing does not exist', $r->body);
    }

    public function test_reflected_method_is_bounded_and_xml_safe(): void
    {
        // The capture class [\w.] stops at '<', so an injected tag is never reflected.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>foo<script>alert(1)</script></methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'reflection-safety fault');
        self::assertStringContainsString('requested method foo does not exist', $r->body);
        self::assertStringNotContainsString('<script', $r->body);
    }

    // --- malformed / empty POST -> parse fault (via the method surface) ----------------------

    public function test_garbage_post_body_is_a_parse_fault(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', 'this is not xml-rpc at all');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        $this->assertWellFormedXml($r->body, 'parse fault');
        self::assertStringContainsString('<int>-32700</int>', $r->body);
        self::assertStringContainsString('parse error. not well formed', $r->body);
        self::assertSame(['attack-wp-xmlrpc-get'], $r->satisfies->templateIds());
    }

    public function test_empty_post_is_a_parse_fault_not_a_405(): void
    {
        // The `method` surface is what distinguishes this from a true GET: both have an empty body,
        // but an empty POST is a malformed methodCall (-32700), not the GET 405.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', null);
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('<int>-32700</int>', $r->body);
    }

    // --- suffix coverage --------------------------------------------------------------------

    public function test_fires_across_prefixed_paths(): void
    {
        foreach (['/wp/xmlrpc.php', '/news/xmlrpc.php', '/wordpress/xmlrpc.php', '/blog/sub/xmlrpc.php'] as $path) {
            $r = $this->serve('POST', $path, '', '<methodCall><methodName>system.listMethods</methodName></methodCall>');
            self::assertNotNull($r, $path);
            self::assertStringContainsString('<methodResponse>', $r->body, $path);
            self::assertSame(['attack-wp-xmlrpc'], $r->satisfies->templateIds(), $path);
        }
    }

    public function test_does_not_fire_on_lookalike_paths(): void
    {
        // The anchored /xmlrpc\.php$ segment boundary means a lookalike never matches.
        self::assertNull($this->serve('POST', '/notxmlrpc.php', '', '<methodName>system.listMethods</methodName>'));
        self::assertNull($this->serve('GET', '/foo.php'));
        self::assertNull($this->serve('GET', '/xmlrpc.php.bak'));
    }

    // --- classify() end-to-end (prefixed reaches attack tier; bare stays shadowed) -----------

    private function fullEngine(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'detect', null, 'matched-only', null, 'coherent', Style::MINIMAL,
            'high', 65536, 0, 0, true /* attackEmulation */
        );

        return new Honeypot($store, $config);
    }

    public function test_classify_prefixed_path_is_attack_class(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/wp/xmlrpc.php', '', [], '<methodCall><methodName>system.listMethods</methodName></methodCall>'),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertContains('attack-wp-xmlrpc', $verdict->detection->templateIds());
    }

    public function test_classify_bare_path_is_still_store_shadowed(): void
    {
        // Documents the deferred Phase-2 gap: bare /xmlrpc.php is an exact-store key answered by the
        // route tier, so it never reaches the attack tier — NOT an ATTACK_CLASS verdict.
        $verdict = $this->fullEngine()->classify(
            new RequestContext('GET', '/xmlrpc.php', '', [], null),
            SiteProfile::empty()
        );
        self::assertNotSame(Verdict::ATTACK_CLASS, $verdict->classification);
    }

    // --- the new `method` surface -----------------------------------------------------------

    public function test_method_surface_exposes_the_http_verb(): void
    {
        // A fixture rule keyed only on the HTTP verb proves surface($r, 'method') returns $r->method
        // — the engine add that lets rule 27 tell an empty POST from a GET.
        $rule = [
            'id' => 'method-surface-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'method', 'regex' => '^POST$']],
            'response' => ['headers' => [], 'body' => 'verb-matched'],
        ];
        $emulator = new TemplateAttackEmulator([$rule]);

        $post = $emulator->emulate(new RequestContext('POST', '/anything', '', [], null));
        self::assertNotNull($post);
        self::assertSame('verb-matched', $post->body);

        self::assertNull($emulator->emulate(new RequestContext('GET', '/anything')));
    }
}
