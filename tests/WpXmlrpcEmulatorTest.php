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
        // No space after the semicolon: real WP emits header('Content-Type: text/plain') and PHP's
        // default_charset appends ';charset=UTF-8' (spaceless), unlike the explicit spaced XML form.
        self::assertSame('text/plain;charset=UTF-8', $r->headers['Content-Type']);
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

    /** Build a system.multicall body wrapping $n wp.getUsersBlogs credential-guess sub-calls. */
    private function multicallBody(int $n, string $method = 'wp.getUsersBlogs'): string
    {
        $sub = '<value><struct>'
            . '<member><name>methodName</name><value><string>' . $method . '</string></value></member>'
            . '<member><name>params</name><value><array><data>'
            . '<value><array><data><value><string>admin</string></value><value><string>guess</string></value></data></array></value>'
            . '</data></array></value></member>'
            . '</struct></value>';
        $body = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
            . '<params><param><value><array><data>';
        for ($i = 0; $i < $n; $i++) {
            $body .= $sub;
        }

        return $body . '</data></array></value></param></params></methodCall>';
    }

    public function test_multicall_fans_out_one_fault_per_subcall(): void
    {
        // The iterate primitive emits ONE result entry per parsed sub-call — a true N-in→N-out
        // multicall, not the old single-entry stopgap.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', $this->multicallBody(3));
        self::assertNotNull($r);
        self::assertSame(['attack-wp-xmlrpc-multicall'], $r->satisfies->templateIds());
        $this->assertWellFormedXml($r->body, 'multicall fan-out');
        self::assertSame(3, substr_count($r->body, '<int>403</int>'), 'three sub-calls must yield three fault entries');
        self::assertStringContainsString('Incorrect username or password.', $r->body);
    }

    public function test_multicall_upholds_the_credential_oracle(): void
    {
        // Even wrapping wp.getUsersBlogs (what brute tools multicall), every entry is the same
        // bad-credentials fault — there is NO success entry: no blog-struct, no isAdmin/blogName.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', $this->multicallBody(5));
        self::assertNotNull($r);
        self::assertSame(5, substr_count($r->body, '<int>403</int>'));
        self::assertDoesNotMatchRegularExpression('/isAdmin|blogName|xmlrpc_url|blogid/i', $r->body);
        // No sub-call is answered with a one-element success array (IXR wraps a multicall success as
        // <array><data><value>…</value></data></array>); the only <string> values are the fault text.
        preg_match_all('/<string>([^<]*)<\/string>/', $r->body, $m);
        foreach ($m[1] as $s) {
            self::assertSame('Incorrect username or password.', $s, 'a multicall entry leaked a non-fault value');
        }
    }

    public function test_multicall_is_amplification_capped(): void
    {
        // A huge sub-call list is clamped by the code constant MAX_ITERATE_ITEMS (64) — no
        // response amplification regardless of how many guesses are packed in.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', $this->multicallBody(1000));
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'capped multicall');
        self::assertSame(64, substr_count($r->body, '<int>403</int>'), 'fan-out must be hard-capped at MAX_ITERATE_ITEMS');
    }

    public function test_multicall_nested_methodname_counts_as_one_subcall(): void
    {
        // ONE real sub-call whose params nest a struct member ALSO named methodName. A flat body-wide
        // count would emit two fault entries; the structural depth-aware count emits exactly one, as
        // real WP does (N-in => N-out) — the nested member sits below the outermost struct depth.
        $body = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
            . '<params><param><value><array><data>'
            . '<value><struct>'
            . '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
            . '<member><name>params</name><value><array><data>'
            . '<value><struct>'
            . '<member><name>methodName</name><value><string>system.listMethods</string></value></member>'
            . '</struct></value>'
            . '</data></array></value></member>'
            . '</struct></value>'
            . '</data></array></value></param></params></methodCall>';
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', $body);
        self::assertNotNull($r);
        self::assertSame(['attack-wp-xmlrpc-multicall'], $r->satisfies->templateIds());
        $this->assertWellFormedXml($r->body, 'nested-methodName multicall');
        self::assertSame(1, substr_count($r->body, '<int>403</int>'), 'a nested methodName must not add a sub-call');
    }

    public function test_multicall_with_no_subcalls_is_an_empty_array(): void
    {
        // A bare system.multicall parses zero sub-calls — real WP returns an empty array, and the
        // response is still well-formed and carries no fault entry.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>system.multicall</methodName></methodCall>');
        self::assertNotNull($r);
        self::assertSame(['attack-wp-xmlrpc-multicall'], $r->satisfies->templateIds());
        $this->assertWellFormedXml($r->body, 'empty multicall');
        self::assertStringContainsString('<array><data>', $r->body);
        self::assertSame(0, substr_count($r->body, '<int>403</int>'));
    }

    // --- demo.addTwoNumbers: real arithmetic via the arith-eval primitive --------------------------

    public function test_add_two_numbers_returns_the_sum(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>demo.addTwoNumbers</methodName>'
            . '<params><param><value><int>44</int></value></param><param><value><int>1</int></value></param></params></methodCall>');
        self::assertNotNull($r);
        self::assertSame(['attack-wp-xmlrpc-addtwo'], $r->satisfies->templateIds());
        self::assertSame(200, $r->status);
        $this->assertWellFormedXml($r->body, 'addTwoNumbers sum');
        self::assertStringContainsString('<int>45</int>', $r->body);
        self::assertStringNotContainsString('{{', $r->body);
    }

    public function test_add_two_numbers_accepts_full_i4_range(): void
    {
        // A 10-digit i4 operand (<= 2147483647) must sum — the capture admits the full i4 width, so a
        // valid large operand returns the real arithmetic, not the invalid-params fault.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>demo.addTwoNumbers</methodName>'
            . '<params><param><value><int>1500000000</int></value></param><param><value><int>1</int></value></param></params></methodCall>');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        $this->assertWellFormedXml($r->body, 'addTwoNumbers full-range sum');
        self::assertStringContainsString('<int>1500000001</int>', $r->body);
        self::assertStringNotContainsString('-32602', $r->body);
    }

    public function test_add_two_numbers_operand_past_i4_faults(): void
    {
        // An operand past the i4 max (> 2147483647) is not a valid i4 — arith-eval's operand bound
        // declines to the plausible -32602 invalid-params fault, never a malformed non-digit sum.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>demo.addTwoNumbers</methodName>'
            . '<params><param><value><int>3000000000</int></value></param><param><value><int>1</int></value></param></params></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'addTwoNumbers out-of-i4 fault');
        self::assertStringContainsString('<int>-32602</int>', $r->body);
        self::assertStringNotContainsString('-32601', $r->body);
    }

    public function test_add_two_numbers_bad_params_is_invalid_params_not_unknown_method(): void
    {
        // A bare/param-less call still matches the addtwo rule; arith-eval declines and the base
        // "invalid method parameters" fault is served — never -32601 (which would out the method).
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>demo.addTwoNumbers</methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'addTwoNumbers invalid params');
        self::assertStringContainsString('<int>-32602</int>', $r->body);
        self::assertStringNotContainsString('-32601', $r->body);
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

    // --- dispatch-accuracy: the ONE captured top-level method decides, not a body re-scan ---------

    public function test_planted_secondary_methodname_does_not_steer_dispatch(): void
    {
        // A decoy <methodName> planted inside a value must NOT flip an auth call to the public list.
        $r = $this->serve(
            'POST',
            '/wp/xmlrpc.php',
            '',
            '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName>'
            . '<value><string><methodName>system.listMethods</string></value></methodCall>'
        );
        self::assertNotNull($r);
        self::assertStringContainsString('<int>403</int>', $r->body);
        self::assertStringContainsString('Incorrect username or password.', $r->body);
        // The full method list must not have been dumped.
        self::assertStringNotContainsString('wp.getMediaItem', $r->body);
    }

    public function test_two_methodcalls_dispatch_on_the_first(): void
    {
        // First top-level method wins (real WP): an auth call followed by demo.sayHello is the oracle.
        $r = $this->serve(
            'POST',
            '/wp/xmlrpc.php',
            '',
            '<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>'
            . '<methodCall><methodName>demo.sayHello</methodName></methodCall>'
        );
        self::assertNotNull($r);
        self::assertStringContainsString('<int>403</int>', $r->body);
        self::assertStringNotContainsString('Hello!', $r->body);
    }

    public function test_decoy_methodname_in_a_comment_is_skipped(): void
    {
        // A leading comment carrying a decoy <methodName> must not be reflected or dispatched.
        $r = $this->serve(
            'POST',
            '/wp/xmlrpc.php',
            '',
            '<!-- <methodName>aaa.decoy</methodName> --><methodCall><methodName>bbb.unknown</methodName></methodCall>'
        );
        self::assertNotNull($r);
        self::assertStringContainsString('requested method bbb.unknown does not exist', $r->body);
        self::assertStringNotContainsString('aaa.decoy', $r->body);

        // Same trick against the oracle: the real method is the auth call, so 403, never the list.
        $r2 = $this->serve(
            'POST',
            '/wp/xmlrpc.php',
            '',
            '<!-- <methodName>system.listMethods</methodName> --><methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>'
        );
        self::assertNotNull($r2);
        self::assertStringContainsString('<int>403</int>', $r2->body);
        self::assertStringNotContainsString('wp.getMediaItem', $r2->body);
    }

    // --- verb-gating: only POST dispatches; every other verb is the 405 ---------------------------

    public function test_non_post_verbs_with_a_methodcall_body_get_405(): void
    {
        foreach (['GET', 'HEAD', 'PUT', 'DELETE'] as $verb) {
            $r = $this->serve($verb, '/wp/xmlrpc.php', '', '<methodCall><methodName>system.listMethods</methodName></methodCall>');
            self::assertNotNull($r, $verb);
            self::assertSame(405, $r->status, $verb);
            self::assertSame('text/plain;charset=UTF-8', $r->headers['Content-Type'], $verb);
            self::assertSame('POST', $r->headers['Allow'], $verb);
            self::assertSame(['attack-wp-xmlrpc-get'], $r->satisfies->templateIds(), $verb);
        }
    }

    public function test_lowercase_post_is_not_dispatched(): void
    {
        // WordPress's method check is case-sensitive: `post` != `POST`, so it is the 405, not a
        // dispatch and not a -32700 parse fault.
        $r = $this->serve('post', '/wp/xmlrpc.php', '', '<methodCall><methodName>system.listMethods</methodName></methodCall>');
        self::assertNotNull($r);
        self::assertSame(405, $r->status);
    }

    // --- listMethods coherence: unique + advertised == handled ------------------------------------

    /** @return string[] the advertised method names from a system.listMethods response */
    private function advertisedMethods(): array
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>system.listMethods</methodName></methodCall>');
        self::assertNotNull($r);
        preg_match_all('/<string>([^<]+)<\/string>/', $r->body, $m);

        return $m[1];
    }

    public function test_listmethods_has_no_duplicates(): void
    {
        $names = $this->advertisedMethods();
        self::assertSame(array_values(array_unique($names)), $names, 'listMethods must have no duplicate names');
        // demo.addTwoNumbers is now handled (by the arith-eval priority-23 rule), so it is advertised.
        self::assertContains('demo.addTwoNumbers', $names, 'demo.addTwoNumbers is now implemented and must be advertised');
    }

    public function test_every_advertised_method_is_handled_not_minus32601(): void
    {
        foreach ($this->advertisedMethods() as $name) {
            $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>' . $name . '</methodName></methodCall>');
            self::assertNotNull($r, $name);
            self::assertStringNotContainsString('-32601', $r->body, $name . ' is advertised but returns "does not exist"');
        }
    }

    // --- public (unauthenticated) mt.* methods must not hit the credential oracle -----------------

    public function test_mt_supported_methods_is_public_and_matches_the_list(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>mt.supportedMethods</methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'mt.supportedMethods');
        self::assertStringContainsString('<array>', $r->body);
        self::assertStringNotContainsString('Incorrect username or password.', $r->body);
        // Real WP returns the same method set as system.listMethods.
        preg_match_all('/<string>([^<]+)<\/string>/', $r->body, $m);
        self::assertSame($this->advertisedMethods(), $m[1]);
    }

    public function test_mt_supported_text_filters_is_public_empty_array(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>mt.supportedTextFilters</methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'mt.supportedTextFilters');
        self::assertStringContainsString('<array>', $r->body);
        self::assertStringNotContainsString('Incorrect username or password.', $r->body);
    }

    public function test_mt_get_trackback_pings_is_public_no_such_post(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>mt.getTrackbackPings</methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'mt.getTrackbackPings');
        self::assertStringContainsString('<int>404</int>', $r->body);
        self::assertStringContainsString('Sorry, no such post.', $r->body);
        self::assertStringNotContainsString('Incorrect username or password.', $r->body);
    }

    public function test_pingback_extensions_getpingbacks_is_handled_zero_egress(): void
    {
        $target = 'http://169.254.169.254/latest/meta-data/';
        $r = $this->serve(
            'POST',
            '/wp/xmlrpc.php',
            '',
            '<methodCall><methodName>pingback.extensions.getPingbacks</methodName>'
            . '<params><param><value><string>' . $target . '</string></value></param></params></methodCall>'
        );
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'getPingbacks');
        self::assertStringContainsString('<int>32</int>', $r->body);
        self::assertStringContainsString('The specified target URL does not exist.', $r->body);
        // Zero egress + no reflection.
        self::assertStringNotContainsString('169.254.169.254', $r->body);
    }

    // --- fault envelope byte structure matches IXR_Error::getXml() ---------------------------------

    public function test_fault_body_is_byte_exact_ixr(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>');
        self::assertNotNull($r);
        $expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            . "<methodResponse>\n"
            . "  <fault>\n"
            . "    <value>\n"
            . "      <struct>\n"
            . "        <member>\n"
            . "          <name>faultCode</name>\n"
            . "          <value><int>403</int></value>\n"
            . "        </member>\n"
            . "        <member>\n"
            . "          <name>faultString</name>\n"
            . "          <value><string>Incorrect username or password.</string></value>\n"
            . "        </member>\n"
            . "      </struct>\n"
            . "    </value>\n"
            . "  </fault>\n"
            . "</methodResponse>\n";
        self::assertSame($expected, $r->body);
    }

    // --- case-sensitivity: path + method names are case-sensitive ---------------------------------

    public function test_uppercase_path_does_not_match(): void
    {
        self::assertNull($this->serve('GET', '/wp/XMLRPC.PHP'));
    }

    public function test_case_variant_method_and_tag(): void
    {
        // A case-variant known method is an unknown method -> -32601 (reflects the variant name).
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>system.LISTMETHODS</methodName></methodCall>');
        self::assertNotNull($r);
        self::assertStringContainsString('<int>-32601</int>', $r->body);

        // A mixed-case <MethodName> tag is not the real tag -> falls to rule 27's -32700 parse fault.
        $r2 = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><MethodName>system.listMethods</MethodName></methodCall>');
        self::assertNotNull($r2);
        self::assertStringContainsString('<int>-32700</int>', $r2->body);
    }

    // --- broadened parsing: attributes + CDATA on <methodName> ------------------------------------

    public function test_methodname_with_attributes_and_cdata_dispatches(): void
    {
        $attr = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName foo="bar">system.listMethods</methodName></methodCall>');
        self::assertNotNull($attr);
        self::assertStringContainsString('<methodResponse>', $attr->body);
        self::assertStringContainsString('wp.getUsersBlogs', $attr->body);

        $cdata = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName><![CDATA[system.listMethods]]></methodName></methodCall>');
        self::assertNotNull($cdata);
        self::assertStringContainsString('wp.getUsersBlogs', $cdata->body);
    }

    // --- empty methodName is an unknown method, not a parse error ----------------------------------

    public function test_empty_methodname_is_minus32601(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName></methodName></methodCall>');
        self::assertNotNull($r);
        // Well-formed envelope, unknown ('') method -> -32601 with the authentic double space.
        self::assertStringContainsString('<int>-32601</int>', $r->body);
        self::assertStringContainsString('requested method  does not exist', $r->body);
    }

    // --- rsd precedence: ?rsd preempts dispatch even on a POST with a methodCall body --------------

    public function test_post_rsd_returns_the_rsd_document(): void
    {
        $r = $this->serve('POST', '/wp/xmlrpc.php', 'rsd', '<methodCall><methodName>system.listMethods</methodName></methodCall>');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('text/xml; charset=UTF-8', $r->headers['Content-Type']);
        self::assertStringContainsString('<rsd', $r->body);
        // The method list must NOT have been dispatched.
        self::assertStringNotContainsString('wp.getUsersBlogs', $r->body);
    }

    // --- PATH_INFO: /xmlrpc.php/extra dispatches; lookalikes still never match ---------------------

    public function test_path_info_after_xmlrpc_php_dispatches(): void
    {
        $get = $this->serve('GET', '/wp/xmlrpc.php/extra');
        self::assertNotNull($get);
        self::assertSame(405, $get->status);

        $post = $this->serve('POST', '/wp/xmlrpc.php/extra', '', '<methodCall><methodName>system.listMethods</methodName></methodCall>');
        self::assertNotNull($post);
        self::assertStringContainsString('<methodResponse>', $post->body);

        // The segment boundary still holds: a suffixed name never matches.
        self::assertNull($this->serve('GET', '/xmlrpc.php.bak'));
        self::assertNull($this->serve('GET', '/wp/notxmlrpc.php'));
    }

    // --- xml-escape backstop for the reflected method ---------------------------------------------

    public function test_reflected_method_is_xml_escaped(): void
    {
        // The capture class [\w.] already stops at '<', so the reflected name is inert; assert the
        // xml: render backstop leaves a normal name intact and never emits a raw tag.
        $r = $this->serve('POST', '/wp/xmlrpc.php', '', '<methodCall><methodName>foo<script>alert(1)</script></methodName></methodCall>');
        self::assertNotNull($r);
        $this->assertWellFormedXml($r->body, 'xml-escaped reflection');
        self::assertStringContainsString('requested method foo does not exist', $r->body);
        self::assertStringNotContainsString('<script', $r->body);
    }
}
