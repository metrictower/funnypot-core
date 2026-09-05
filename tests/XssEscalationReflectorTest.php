<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Closure;
use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The bounded RAW escalation companion (`attack-xss-escalation`) of the alphanumeric reflection
 * baseline, on the same owned search path. A scanner's confirmation stages — dalfox's batched
 * special-character probe and generated tags, nuclei's percent-encoded `'"><N>` breakout — carry
 * markup bytes the baseline refuses; this rule reflects them RAW through
 * {{urldecode-ascii:match.value}} (one form-decode, then 1..512 printable-ASCII bytes or nothing),
 * so the scanner's own payload comes back byte-for-byte and its verdict is honest.
 *
 * It is a reflects_input rule, so it serves ONLY when all three gate terms hold (isolated origin,
 * xss class on, request-bound authorizer literally true). Gate-OFF cases prove no unescaped markup
 * is ever served while the detection is still recorded; gate-ON cases prove the bytes and the
 * headers. Driven through the real Honeypot::classify()/respond() over the production compiled store.
 */
final class XssEscalationReflectorTest extends TestCase
{
    private const PATH = '/products/quick-search';
    private const ID = 'attack-xss-escalation';
    private const BASELINE_ID = 'attack-xss-baseline';
    private const ATTACK_ARTIFACT = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    // dalfox's bracketed discovery marker halves (alnum) that wrap a probed special character.
    private const PROBE_OPEN = 'dlx0a1b2c3d';
    private const PROBE_CLOSE = 'xld8c9d0e1f';
    private const SPECIAL_PROBE_CHARS = ['/', '\\', '\'', '{', '`', '<', '>', '"', '(', ')', ';', '=', '|', '}', '[', '.', ':', ']', '+', ',', '$', '-'];

    // nuclei's reflected-XSS DAST payload shape `'"><{{first}}>`; sent percent-encoded, matched raw.
    private const NUCLEI_PAYLOAD = '\'"><12345>';

    // The exact defense-in-depth header set the template authors, beyond the normal envelope.
    private const HEADERS = [
        'Content-Type' => 'text/html; charset=utf-8',
        'Content-Security-Policy' => "sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        'Cache-Control' => 'no-store',
        'Referrer-Policy' => 'no-referrer',
        'X-Content-Type-Options' => 'nosniff',
        'Cross-Origin-Resource-Policy' => 'same-origin',
        'Cross-Origin-Opener-Policy' => 'same-origin',
    ];

    /** Test-only evidence: vouches for every request so the gate-ON rows can run. */
    private static function vouch(): Closure
    {
        return static function (RequestContext $r, string $class): bool { return true; };
    }

    /**
     * @param array<string,bool> $reflectClasses
     */
    private function honeypot(bool $isolatedOrigin, ?Closure $authorizer = null, array $reflectClasses = []): Honeypot
    {
        $config = new Config(
            'respond',                                                  // mode
            static function (RequestContext $r): bool { return true; }, // gate
            'matched-only',                                             // pathScope
            null,                                                       // personaSeed
            'coherent',                                                 // personaBreadth
            Style::MINIMAL,                                             // responseStyle
            'high',                                                     // severityCeiling
            65536,                                                      // maxBodyBytes
            0,                                                          // latencyMs
            0,                                                          // latencyJitterMs
            true                                                        // attackEmulation
        );
        $config->isolatedOrigin = $isolatedOrigin;
        $config->reflectClasses = $reflectClasses;
        $config->reflectorAuthorizer = $authorizer;

        return Honeypot::default($config);
    }

    private function gateOn(): Honeypot
    {
        return $this->honeypot(true, self::vouch());
    }

    private static function req(string $query, string $method = 'GET'): RequestContext
    {
        return new RequestContext($method, self::PATH, $query);
    }

    /** @return string[] */
    private function ids(Honeypot $hp, RequestContext $r): array
    {
        return $hp->classify($r, SiteProfile::empty())->detection->templateIds();
    }

    /** The reflected slot: the text between the page's one <span> pair; null when the body has none. */
    private static function slot(string $body): ?string
    {
        return preg_match('~<span>(.*?)</span>~s', $body, $m) === 1 ? $m[1] : null;
    }

    // --- gate OFF: detection kept, nothing unescaped served ---

    public function test_gate_off_detects_but_serves_no_attacker_bytes(): void
    {
        $q = 'q=' . rawurlencode(self::NUCLEI_PAYLOAD);
        $off = [
            'embedded default' => $this->honeypot(false),
            'embedded + authorizer' => $this->honeypot(false, self::vouch()),
            'isolated, no authorizer' => $this->honeypot(true),
            'isolated, authorizer false' => $this->honeypot(true, static function (RequestContext $r, string $c): bool { return false; }),
            'isolated, authorizer throws' => $this->honeypot(true, static function (RequestContext $r, string $c): bool { throw new \RuntimeException('adapter fault'); }),
            'isolated, xss class off' => $this->honeypot(true, self::vouch(), ['xss' => false]),
        ];
        foreach ($off as $label => $hp) {
            $verdict = $hp->classify(self::req($q), SiteProfile::empty());
            self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, $label);
            self::assertSame([self::ID], $verdict->detection->templateIds(), $label);
            self::assertNull($hp->respond(self::req($q)), "{$label}: must withhold");
        }
    }

    public function test_position_blind_synthesize_withholds_even_when_authorized(): void
    {
        $hp = $this->gateOn();
        $verdict = $hp->classify(self::req('q=' . rawurlencode(self::NUCLEI_PAYLOAD)), SiteProfile::empty());
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId);
        self::assertNull($hp->synthesize($verdict, SiteProfile::empty(), 'seed'));
        self::assertNull($hp->synthesizeFromHandle($verdict->fakeHandle, SiteProfile::empty(), 'seed'));
    }

    /**
     * The default-install change on the owned path: a non-alphanumeric `q` used to fall through to
     * a canned decline page; it now matches this (suppressed) rule ⇒ the host's own 404. No attacker
     * byte was served before and none is now — the recorded detection id is what changes.
     */
    public function test_embedded_default_host_404s_non_alnum_q_on_the_owned_path(): void
    {
        $hp = $this->honeypot(false);
        foreach (['q=abc<def', 'q=%3Cscript%3E', 'q=a b', 'q=' . str_repeat('a', 65)] as $q) {
            self::assertSame([self::ID], $this->ids($hp, self::req($q)), $q);
            self::assertNull($hp->respond(self::req($q)), $q);
        }
        // The alphanumeric baseline is untouched: same rule, no gate.
        $base = $hp->respond(self::req('q=laptop'));
        self::assertNotNull($base);
        self::assertSame(self::BASELINE_ID, $base->servedBy->ruleId);
    }

    // --- gate ON: the scanner shapes come back raw, at the owned route only ---

    public function test_dalfox_batched_special_probe_reflects_raw(): void
    {
        $hp = $this->gateOn();
        foreach (self::SPECIAL_PROBE_CHARS as $c) {
            foreach (['raw' => $c, 'enc' => rawurlencode($c)] as $form => $wire) {
                // A raw '+' on the wire is a space to a GET form sink, so it is the one probe byte that
                // legitimately does NOT survive; percent-encoded it does.
                $expected = self::PROBE_OPEN . (($form === 'raw' && $c === '+') ? ' ' : $c) . self::PROBE_CLOSE;
                $label = "{$form} " . bin2hex($c);
                $resp = $hp->respond(self::req('q=' . self::PROBE_OPEN . $wire . self::PROBE_CLOSE));
                self::assertNotNull($resp, $label);
                self::assertSame(self::ID, $resp->servedBy->ruleId, $label);
                self::assertSame($expected, self::slot($resp->body), $label);
            }
        }
        // The batched form dalfox actually sends: every special character in ONE value.
        $batch = self::PROBE_OPEN . implode('', self::SPECIAL_PROBE_CHARS) . self::PROBE_CLOSE;
        $resp = $hp->respond(self::req('q=' . rawurlencode($batch)));
        self::assertNotNull($resp);
        self::assertSame(self::ID, $resp->servedBy->ruleId);
        self::assertSame($batch, self::slot($resp->body));
    }

    public function test_dalfox_generated_tags_reflect_raw_including_slash_event_syntax(): void
    {
        $hp = $this->gateOn();
        $tags = [
            // form-encoded the way a Go/Rust query encoder emits it: '+' for space
            'img onerror, plus-encoded' => ['q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E', '<img src=x onerror=alert(1)>'],
            'svg slash-event'           => ['q=<svg/onload=alert(1)>', '<svg/onload=alert(1)>'],
            'svg slash-event, encoded'  => ['q=%3Csvg%2Fonload%3Dalert(1)%3E', '<svg/onload=alert(1)>'],
            'details slash-event'       => ['q=<details/open/ontoggle=alert(1)>', '<details/open/ontoggle=alert(1)>'],
            'attribute breakout'        => ['q="onmouseover=alert(1)', '"onmouseover=alert(1)'],
            'marker-wrapped tag'        => ['q=' . self::PROBE_OPEN . '<b>' . self::PROBE_CLOSE, self::PROBE_OPEN . '<b>' . self::PROBE_CLOSE],
        ];
        foreach ($tags as $label => [$q, $expected]) {
            $resp = $hp->respond(self::req($q));
            self::assertNotNull($resp, $label);
            self::assertSame(self::ID, $resp->servedBy->ruleId, $label);
            self::assertSame($expected, self::slot($resp->body), $label);
        }
    }

    public function test_full_tag_shapes_stay_with_attack_xss_at_equal_priority(): void
    {
        // Compile order is priority then id: 'attack-xss' < 'attack-xss-escalation', and matchRule()
        // is first-match-wins, so the older broad reflector keeps its whole-tag shapes deterministically.
        $hp = $this->gateOn();
        foreach (['q=<script>alert(1)</script>', 'q=<img src=x onerror=alert(1)>', 'q=<svg onload=alert(1)></svg>'] as $q) {
            $resp = $hp->respond(self::req($q));
            self::assertNotNull($resp, $q);
            self::assertSame('attack-xss', $resp->servedBy->ruleId, $q);
        }

        $ids = array_map(static function (array $r): string { return (string) $r['id']; }, require self::ATTACK_ARTIFACT);
        $baseline = array_search(self::BASELINE_ID, $ids, true);
        $xss = array_search('attack-xss', $ids, true);
        $escalation = array_search(self::ID, $ids, true);
        self::assertTrue($baseline < $xss && $xss < $escalation, 'compiled order must be baseline, attack-xss, escalation');
    }

    public function test_nuclei_percent_encoded_breakout_reflects_raw_in_text_html(): void
    {
        // nuclei's reflected-XSS DAST template: payload `'"><{{first}}>`, URL-encoded on the wire,
        // matched UNENCODED in the body together with a text/html Content-Type.
        $resp = $this->gateOn()->respond(self::req('q=' . rawurlencode(self::NUCLEI_PAYLOAD)));
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertSame(self::ID, $resp->servedBy->ruleId);
        self::assertStringStartsWith('text/html', (string) $resp->headers['Content-Type']);
        self::assertStringContainsString(self::NUCLEI_PAYLOAD, $resp->body);
        self::assertSame(self::NUCLEI_PAYLOAD, self::slot($resp->body));
        // Decoded exactly once: the encoded form is nowhere in the page.
        self::assertStringNotContainsString('%3C', $resp->body);
    }

    public function test_only_the_q_key_on_the_owned_get_route_reflects(): void
    {
        $hp = $this->gateOn();
        $payload = self::PROBE_OPEN . '<' . self::PROBE_CLOSE;

        // (i) Another path never reaches this rule, and nothing echoes the payload.
        $elsewhere = new RequestContext('GET', '/search', 'q=' . $payload);
        self::assertNotContains(self::ID, $this->ids($hp, $elsewhere));
        $off = $hp->respond($elsewhere);
        if ($off !== null) {
            self::assertStringNotContainsString($payload, $off->body);
        }

        // (ii) Another key on the owned path never reaches this rule.
        self::assertNotContains(self::ID, $this->ids($hp, self::req('search=' . $payload)));

        // (iii) A duplicate q reflects the FIRST matching value only; unrelated params never enter the slot.
        $resp = $hp->respond(self::req('q=' . $payload . '&q=second<one'));
        self::assertNotNull($resp);
        self::assertSame($payload, self::slot($resp->body));
        self::assertStringNotContainsString('second<one', $resp->body);
        $resp = $hp->respond(self::req('page=2&q=' . $payload . '&sort=<desc>'));
        self::assertNotNull($resp);
        self::assertSame($payload, self::slot($resp->body));
        self::assertStringNotContainsString('<desc>', $resp->body);

        // (iv) A POST carrying the same query does not reach this GET rule.
        self::assertNotContains(self::ID, $this->ids($hp, self::req('q=' . $payload, 'POST')));

        // (v) The trailing-slash variant is the same owned route.
        $resp = $hp->respond(new RequestContext('GET', self::PATH . '/', 'q=' . $payload));
        self::assertNotNull($resp);
        self::assertSame(self::ID, $resp->servedBy->ruleId);
    }

    // --- the decode boundaries, end-to-end: forbidden bytes never appear, whoever serves ---

    /**
     * @dataProvider rejectedValueProvider
     */
    public function test_rejected_values_never_reach_the_page(string $label, string $wireValue, string $mustNotAppear): void
    {
        $resp = $this->gateOn()->respond(self::req('q=' . $wireValue));
        // Whatever serves (this rule with an empty slot, another decoy, or nothing), the bytes are absent.
        if ($resp !== null) {
            self::assertStringNotContainsString($mustNotAppear, $resp->body, $label);
            if ($resp->servedBy->ruleId === self::ID) {
                self::assertSame('', self::slot($resp->body), "{$label}: slot must be empty");
            }
        } else {
            self::assertNull($resp);
        }
    }

    /**
     * @return iterable<string,array{0:string,1:string,2:string}>
     */
    public static function rejectedValueProvider(): iterable
    {
        // Every C0 control, percent-encoded (the raw class admits the encoding; the decode rejects it).
        for ($b = 0; $b < 0x20; $b++) {
            $c = chr($b);
            yield sprintf('enc C0 0x%02x', $b) => [sprintf('enc-c0-%02x', $b), 'a' . rawurlencode($c) . 'b', 'a' . $c . 'b'];
        }
        yield 'enc DEL' => ['enc-del', 'a%7Fb', "a\x7fb"];
        // Raw controls the raw class admits (everything but CR/LF/NUL) are rejected by the decode.
        yield 'raw TAB' => ['raw-tab', "a\tb", "a\tb"];
        yield 'raw ESC' => ['raw-esc', "a\x1bb", "a\x1bb"];
        yield 'raw DEL' => ['raw-del', "a\x7fb", "a\x7fb"];
        // Raw CR/LF/NUL: the raw capture class itself refuses, so the rule declines whole.
        yield 'raw CR' => ['raw-cr', "a\rb", "a\rb"];
        yield 'raw LF' => ['raw-lf', "a\nb", "a\nb"];
        yield 'raw NUL' => ['raw-nul', "a\x00b", "a\x00b"];
        yield 'enc CRLF' => ['enc-crlf', 'a%0d%0ab', "a\r\nb"];
        yield 'enc NUL' => ['enc-nul', 'a%00b', "a\x00b"];
        // High bytes, raw and encoded (lone continuation, latin-1, valid UTF-8).
        yield 'enc utf-8' => ['enc-utf8', rawurlencode('ünïcode'), 'ünïcode'];
        yield 'raw utf-8' => ['raw-utf8', "a\xc3\xbcb", "a\xc3\xbcb"];
        yield 'enc 0x80' => ['enc-80', 'a%80b', "a\x80b"];
        yield 'enc 0xff' => ['enc-ff', 'a%ffb', "a\xffb"];
        // 513 decoded bytes: over the cap, so nothing (non-alnum so the baseline cannot claim it).
        yield '513 decoded' => ['513', '<' . str_repeat('a', 512), '<' . str_repeat('a', 512)];
        // 1537 raw bytes: over the raw class cap, so the rule declines whole.
        yield '1537 raw' => ['1537', '<' . str_repeat('a', 1536), '<' . str_repeat('a', 1536)];
    }

    public function test_512_decoded_bytes_reflect_and_513_do_not(): void
    {
        $hp = $this->gateOn();
        $ok = '<' . str_repeat('a', 511); // 512 bytes; non-alnum so the baseline cannot claim it
        $resp = $hp->respond(self::req('q=' . $ok));
        self::assertNotNull($resp);
        self::assertSame(self::ID, $resp->servedBy->ruleId);
        self::assertSame($ok, self::slot($resp->body));

        // Fully percent-encoded, the same 512 bytes are 1536 raw bytes — exactly the raw class cap.
        $encoded = '';
        foreach (str_split($ok) as $ch) {
            $encoded .= sprintf('%%%02X', ord($ch));
        }
        self::assertSame(1536, strlen($encoded));
        $resp = $hp->respond(self::req('q=' . $encoded));
        self::assertNotNull($resp);
        self::assertSame(self::ID, $resp->servedBy->ruleId);
        self::assertSame($ok, self::slot($resp->body));

        $over = '<' . str_repeat('a', 512); // 513 bytes
        $resp = $hp->respond(self::req('q=' . $over));
        self::assertNotNull($resp);
        self::assertSame(self::ID, $resp->servedBy->ruleId);
        self::assertSame('', self::slot($resp->body));
        self::assertStringNotContainsString($over, $resp->body);
    }

    public function test_double_encoding_is_decoded_exactly_once(): void
    {
        $hp = $this->gateOn();
        // %250a is ONE decode away from the printable text "%0a": served as those three characters,
        // never turned into a LF.
        $resp = $hp->respond(self::req('q=a%250ab'));
        self::assertNotNull($resp);
        self::assertSame('a%0ab', self::slot($resp->body));
        self::assertStringNotContainsString("a\nb", $resp->body);
        // %253C stays the text "%3C", never a '<'.
        $resp = $hp->respond(self::req('q=x%253Cy'));
        self::assertNotNull($resp);
        self::assertSame('x%3Cy', self::slot($resp->body));
        // An invalid triplet stays literal '%' text (urldecode semantics).
        $resp = $hp->respond(self::req('q=100%25%zz<'));
        self::assertNotNull($resp);
        self::assertSame('100%%zz<', self::slot($resp->body));
    }

    // --- the response envelope: exact headers, nothing else attacker-steerable ---

    public function test_response_carries_exactly_the_authored_headers_and_no_cookie_cors_or_redirect(): void
    {
        $resp = $this->gateOn()->respond(self::req('q=' . rawurlencode(self::NUCLEI_PAYLOAD)));
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        foreach (self::HEADERS as $name => $value) {
            self::assertArrayHasKey($name, $resp->headers);
            self::assertSame($value, $resp->headers[$name], $name);
        }
        // Beyond the authored set only the front-layer envelope (X-Request-Id) rides along.
        self::assertSame(['X-Request-Id'], array_keys(array_diff_key($resp->headers, self::HEADERS)));
        foreach (array_keys($resp->headers) as $name) {
            $lower = strtolower((string) $name);
            self::assertStringNotContainsString('set-cookie', $lower);
            self::assertStringNotContainsString('access-control-', $lower);
            self::assertNotSame('location', $lower);
        }
    }

    public function test_body_has_no_script_subresource_or_external_url_outside_the_one_slot(): void
    {
        $payload = 'S3NT<1>NEL';
        $resp = $this->gateOn()->respond(self::req('q=' . $payload));
        self::assertNotNull($resp);
        self::assertSame(self::ID, $resp->servedBy->ruleId);
        $body = $resp->body;

        // The sentinel appears exactly once — inside the span — and nowhere else.
        self::assertSame(1, substr_count($body, $payload));
        self::assertSame($payload, self::slot($body));

        // With the slot removed, the authored page carries no script, no subresource, no external URL.
        $authored = str_replace($payload, '', $body);
        self::assertStringNotContainsString('<script', strtolower($authored));
        self::assertStringNotContainsString('://', $authored);
        self::assertStringNotContainsString('//', $authored);
        self::assertSame(0, preg_match('/\s(src|href)\s*=/i', $authored));
        // The only form target is the owned relative path.
        self::assertSame(1, preg_match_all('/action="([^"]*)"/', $authored, $m));
        self::assertSame([self::PATH], $m[1]);
    }

    public function test_reflected_bytes_are_never_fingerprint_scanned(): void
    {
        // The fingerprint gate covers authored bytes only (compile time). A reflected value that
        // happens to spell an upstream-detector word must come back like any other: a runtime scan
        // of reflected bytes would let an attacker probe the denylist with two requests. (The token
        // is split so this file never carries the literal.)
        $word = 'Mod' . 'Security';
        $resp = $this->gateOn()->respond(self::req('q=<' . $word . '>'));
        self::assertNotNull($resp);
        self::assertSame(self::ID, $resp->servedBy->ruleId);
        self::assertSame('<' . $word . '>', self::slot($resp->body));
    }

    // --- determinism + one page family with the baseline ---

    public function test_served_bytes_are_deterministic_and_share_the_baseline_page(): void
    {
        $hp = $this->gateOn();
        $a = $hp->respond(self::req('q=%3Cb%3E'));
        $b = $hp->respond(self::req('q=%3Cb%3E'));
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body);

        // The same page as the baseline serves, differing only in the slot: the two rules present ONE
        // coherent search page on the owned route.
        $base = $hp->respond(self::req('q=laptop'));
        self::assertNotNull($base);
        self::assertSame(self::BASELINE_ID, $base->servedBy->ruleId);
        self::assertSame(str_replace('laptop', '<b>', $base->body), $a->body);
    }

    // --- the compiled shape is pinned + the YAML recompiles to the committed entry ---

    public function test_compiled_shape_is_pinned(): void
    {
        $rule = TemplateAttackEmulator::fromFile(self::ATTACK_ARTIFACT)->ruleById(self::ID);

        self::assertNotNull($rule);
        self::assertSame(200, $rule['status']);
        self::assertSame('medium', $rule['severity']);
        self::assertSame(['attack', 'xss', 'reflection-baseline'], $rule['tags']);
        // The reflector marker + its class: exactly one flag, exactly one class.
        self::assertTrue($rule['reflects_input']);
        self::assertSame('xss', $rule['reflect_class']);
        // Scoped to one path via the literal prefilter.
        self::assertSame('/products/quick-search', $rule['lit']);
        self::assertSame('path', $rule['lit_in']);
        // GET only, the exact path, and the EXACT bounded raw capture with capture:true.
        self::assertSame(['in' => 'method', 'regex' => '^GET$'], $rule['match'][0]);
        self::assertSame(['in' => 'path', 'regex' => '^/products/quick-search/?$'], $rule['match'][1]);
        self::assertSame('query', $rule['match'][2]['in']);
        self::assertTrue($rule['match'][2]['capture']);
        self::assertSame('(?:^|&)q=(?P<value>[^&\r\n\x00]{1,1536})(?:&|$)', $rule['match'][2]['regex']);
        // The exact header set.
        self::assertSame(self::HEADERS, $rule['response']['headers']);
        // Exactly two directives in the body: the persona name and the ONE bounded raw slot.
        preg_match_all('/\{\{\s*([^}]+?)\s*\}\}/', (string) $rule['response']['body'], $m);
        self::assertSame(['persona.company.name', 'urldecode-ascii:match.value'], $m[1]);
    }

    public function test_yaml_recompiles_to_the_committed_artifact_entry(): void
    {
        $dir = sys_get_temp_dir() . '/funnypot-xssescalation-' . getmypid() . '-' . uniqid();
        self::assertTrue(mkdir($dir, 0775, true) || is_dir($dir));
        copy(__DIR__ . '/../templates/attack/65-xss-reflection-escalation.yaml', $dir . '/rule.yaml');
        try {
            $compiled = (new EmulatorCompiler())->compile($dir);
        } finally {
            @unlink($dir . '/rule.yaml');
            @rmdir($dir);
        }

        $fresh = null;
        foreach ($compiled as $rule) {
            if (($rule['id'] ?? '') === self::ID) {
                $fresh = $rule;
            }
        }
        self::assertNotNull($fresh, 'the single-YAML compile must yield the escalation rule');

        $committed = TemplateAttackEmulator::fromFile(self::ATTACK_ARTIFACT)->ruleById(self::ID);
        self::assertSame($committed, $fresh, 'committed artifact entry must match a fresh recompile (zero hand-edit drift)');
    }
}
