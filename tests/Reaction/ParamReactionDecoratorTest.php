<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use Closure;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Reaction\ParamIntent;
use Funnypot\Core\Reaction\ParamReactionDecorator;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * The decorator's eligibility matrix and the two documented differentials. Every decline returns null,
 * so the caller keeps the exact base object; a success returns a NEW response with the base's status,
 * headers and Detection. The B1 oracle cases prove the reflected value is NEVER fingerprint-scanned.
 */
final class ParamReactionDecoratorTest extends TestCase
{
    private const DEPLOY_SEED = 4242;

    private static function vouch(): Closure
    {
        return static function (RequestContext $r, string $class): bool { return true; };
    }

    /** A fully-open config (isolated + authorized + reactive + styled), the only config that reacts. */
    private function openConfig(): Config
    {
        $config = new Config();
        $config->responseStyle = Style::REALISTIC;
        $config->isolatedOrigin = true;
        $config->reflectorAuthorizer = self::vouch();
        $config->paramReactivity = true;

        return $config;
    }

    private function decorator(?Config $config = null, ?callable $guardLoader = null): ParamReactionDecorator
    {
        return new ParamReactionDecorator($config ?? $this->openConfig(), self::DEPLOY_SEED, $guardLoader);
    }

    private static function request(): RequestContext
    {
        return new RequestContext('GET', '/shop', 'q=hello', [], null, 'shop.example');
    }

    private static function searchHandle(string $value = 'hello'): FakeHandle
    {
        return FakeHandle::route('GET /shop', ParamIntent::create(ParamIntent::KIND_SEARCH_RESULT, 'q', $value));
    }

    /** @param array<string,mixed> $extra @param array<string,string|string[]> $headers */
    private static function base(array $headers, string $body, int $status = 200): SynthesizedResponse
    {
        return new SynthesizedResponse($status, $headers, $body, Detection::none());
    }

    /** @param array<string,mixed> $bundle */
    private function decorate(SynthesizedResponse $base, array $bundle, ?FakeHandle $handle = null, ?Config $config = null): ?SynthesizedResponse
    {
        return $this->decorator($config)->decorate($base, $bundle, $handle ?? self::searchHandle(), self::request());
    }

    // --- positive ---------------------------------------------------------------------------------

    public function test_html_fragment_lands_before_the_last_body_close(): void
    {
        $base = self::base(['Content-Type' => 'text/html'], "<html><body><p>Welcome</p></body></html>");
        $out = $this->decorate($base, ['bw' => ['Welcome']]);

        self::assertNotNull($out);
        self::assertStringContainsString('search-results', $out->body);
        $bodyClose = strripos($out->body, '</body>');
        $panel = strpos($out->body, 'search-results');
        self::assertNotFalse($panel);
        self::assertLessThan($bodyClose, $panel, 'the panel must sit before </body>');
        // Base status/headers/Detection are preserved by value.
        self::assertSame(200, $out->status);
        self::assertSame($base->headers, $out->headers);
        self::assertSame($base->satisfies, $out->satisfies);
    }

    public function test_html_without_body_close_is_appended(): void
    {
        $base = self::base(['Content-Type' => 'text/html'], "<div>partial</div>");
        $out = $this->decorate($base, ['bw' => ['partial']]);

        self::assertNotNull($out);
        self::assertStringStartsWith('<div>partial</div>', $out->body);
        self::assertStringContainsString('search-results', $out->body);
    }

    public function test_text_plain_fragment_is_newline_appended(): void
    {
        $base = self::base(['Content-Type' => 'text/plain'], "welcome");
        $out = $this->decorate($base, ['bw' => ['welcome']]);

        self::assertNotNull($out);
        self::assertStringStartsWith("welcome\n", $out->body);
        self::assertStringContainsString('search results for:', $out->body);
    }

    public function test_html_value_is_entity_encoded_never_raw_markup(): void
    {
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        $out = $this->decorate($base, ['bw' => ['ok']], self::searchHandle('"><script>alert(1)</script>'));

        self::assertNotNull($out);
        self::assertStringNotContainsString('<script>alert(1)', $out->body);
        self::assertStringContainsString('&lt;script&gt;', $out->body);
        self::assertStringContainsString('&quot;&gt;', $out->body);
    }

    // --- B1 oracle: the reflected value is never fingerprint-scanned ------------------------------

    /**
     * @dataProvider denylistValueProvider
     */
    public function test_a_denylisted_value_still_decorates(string $value, string $needle): void
    {
        // nf=[] so the bundle imposes no negative matcher. If the final body (or the value) were
        // fingerprint-scanned, each of these would DECLINE — that is the differential oracle B1 forbids.
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        $out = $this->decorate($base, ['bw' => ['ok']], self::searchHandle($value));

        self::assertNotNull($out, "denylisted value {$value} must still decorate");
        self::assertStringContainsString($needle, $out->body);
    }

    /** @return iterable<string,array{0:string,1:string}> */
    public static function denylistValueProvider(): iterable
    {
        yield 'bare crs id' => ['942100', '942100'];
        yield 'modsecurity' => ['ModSecurity', 'ModSecurity'];
        yield 'owasp crs' => ['OWASP_CRS', 'OWASP_CRS'];
        yield 'secrule' => ['SecRule', 'SecRule'];
    }

    public function test_bundle_nf_is_the_one_accepted_differential(): void
    {
        // A value that hits the bundle's OWN negative matcher declines — matcher truth for the scanner
        // that sent the query, not detector vocabulary.
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        $out = $this->decorate($base, ['bw' => ['ok'], 'nf' => ['zzforbidden']], self::searchHandle('zzforbidden'));

        self::assertNull($out, 'a value that breaks the bundle nf must decline');
    }

    // --- guard: loaded once, fail-closed ---------------------------------------------------------

    public function test_guard_is_loaded_once_across_many_calls(): void
    {
        $calls = 0;
        $loader = static function () use (&$calls): ?FingerprintGuard {
            $calls++;

            return FingerprintGuard::fromPackage();
        };
        $decorator = $this->decorator($this->openConfig(), $loader);
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");

        for ($i = 0; $i < 50; $i++) {
            $decorator->decorate($base, ['bw' => ['ok']], self::searchHandle('run' . $i), self::request());
        }
        self::assertSame(1, $calls, 'the fingerprint guard must load once per decorator instance');
    }

    public function test_a_null_guard_declines_fail_closed(): void
    {
        $decorator = $this->decorator($this->openConfig(), static function (): ?FingerprintGuard { return null; });
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");

        self::assertNull($decorator->decorate($base, ['bw' => ['ok']], self::searchHandle(), self::request()));
    }

    public function test_a_throwing_guard_loader_declines_without_throwing(): void
    {
        $decorator = $this->decorator($this->openConfig(), static function (): ?FingerprintGuard {
            throw new \RuntimeException('boom');
        });
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");

        self::assertNull($decorator->decorate($base, ['bw' => ['ok']], self::searchHandle(), self::request()));
    }

    // --- negatives: every one returns null (the caller keeps the base) ---------------------------

    /**
     * @dataProvider statusProvider
     */
    public function test_ineligible_status_declines(int $status): void
    {
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>", $status);
        self::assertNull($this->decorate($base, ['bw' => ['ok']]));
    }

    /** @return iterable<string,array{0:int}> */
    public static function statusProvider(): iterable
    {
        yield '204' => [204];
        yield '205' => [205];
        yield '301' => [301];
        yield '302' => [302];
        yield '304' => [304];
    }

    /**
     * @dataProvider ineligibleBundleProvider
     * @param array<string,mixed> $bundle
     */
    public function test_ineligible_bundle_shape_declines(array $bundle): void
    {
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, $bundle));
    }

    /** @return iterable<string,array{0:array<string,mixed>}> */
    public static function ineligibleBundleProvider(): iterable
    {
        yield 'sz eq' => [['bw' => ['ok'], 'sz' => ['eq' => 20]]];
        yield 'sz min' => [['bw' => ['ok'], 'sz' => ['min' => 5]]];
        yield 'sz max' => [['bw' => ['ok'], 'sz' => ['max' => 999]]];
        yield 'exclusive' => [['bw' => ['ok'], 'x' => true]];
        yield 'regex' => [['bw' => ['ok'], 'rx' => ['ok']]];
        yield 'binary' => [['bin' => 'AAAA']];
    }

    /**
     * @dataProvider ineligibleContentTypeProvider
     */
    public function test_ineligible_content_type_declines(string $contentType): void
    {
        $base = self::base(['Content-Type' => $contentType], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']]));
    }

    /** @return iterable<string,array{0:string}> */
    public static function ineligibleContentTypeProvider(): iterable
    {
        yield 'json' => ['application/json'];
        yield 'xml' => ['text/xml'];
        yield 'html iso' => ['text/html; charset=iso-8859-1'];
        yield 'octet' => ['application/octet-stream'];
        yield 'css' => ['text/css'];
    }

    public function test_utf8_charset_is_eligible(): void
    {
        $base = self::base(['Content-Type' => 'text/html; charset=utf-8'], "<html><body>ok</body></html>");
        self::assertNotNull($this->decorate($base, ['bw' => ['ok']]));
    }

    public function test_list_valued_header_declines(): void
    {
        $base = self::base(['Content-Type' => 'text/html', 'Set-Cookie' => ['a=1', 'b=2']], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']]));
    }

    /**
     * @dataProvider forbiddenHeaderProvider
     */
    public function test_forbidden_header_declines(string $name): void
    {
        $base = self::base(['Content-Type' => 'text/html', $name => 'x'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']]));
    }

    /** @return iterable<string,array{0:string}> */
    public static function forbiddenHeaderProvider(): iterable
    {
        yield 'Location' => ['Location'];
        yield 'Refresh' => ['Refresh'];
        yield 'Set-Cookie' => ['Set-Cookie'];
        yield 'Content-Disposition' => ['Content-Disposition'];
        yield 'Content-Encoding' => ['Content-Encoding'];
        yield 'Content-Length' => ['Content-Length'];
        yield 'Content-Range' => ['Content-Range'];
        yield 'Transfer-Encoding' => ['Transfer-Encoding'];
    }

    public function test_minimal_style_declines(): void
    {
        $config = $this->openConfig();
        $config->responseStyle = Style::MINIMAL;
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], null, $config));
    }

    public function test_param_reactivity_off_declines(): void
    {
        $config = $this->openConfig();
        $config->paramReactivity = false;
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], null, $config));
    }

    public function test_embedded_origin_declines(): void
    {
        $config = $this->openConfig();
        $config->isolatedOrigin = false;
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], null, $config));
    }

    public function test_subtracted_class_declines(): void
    {
        $config = $this->openConfig();
        $config->reflectClasses = [ParamReactionDecorator::REFLECT_CLASS => false];
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], null, $config));
    }

    public function test_missing_authorizer_declines(): void
    {
        $config = $this->openConfig();
        $config->reflectorAuthorizer = null;
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], null, $config));
    }

    public function test_null_request_declines(): void
    {
        // The position-blind port carries no request, hence no evidence: withheld.
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorator()->decorate($base, ['bw' => ['ok']], self::searchHandle(), null));
    }

    public function test_non_route_handle_declines(): void
    {
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], FakeHandle::attack('attack-x')));
    }

    public function test_route_handle_without_intent_declines(): void
    {
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], FakeHandle::route('GET /shop')));
    }

    public function test_forged_intent_object_declines(): void
    {
        // A public property replaced with a malformed intent (bad kind) revalidates to null.
        $handle = self::searchHandle();
        $handle->paramIntent = self::forgedIntent();
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], $handle));
    }

    private static function forgedIntent(): ParamIntent
    {
        // Build a structurally-present but invalid ParamIntent via reflection (bypassing the factories),
        // as a hostile/corrupt caller could — the decorator's tryFromArray revalidation must reject it.
        $ref = new \ReflectionClass(ParamIntent::class);
        /** @var ParamIntent $obj */
        $obj = $ref->newInstanceWithoutConstructor();
        $obj->kind = 'not-a-real-kind';
        $obj->key = 'q';
        $obj->value = 'x';

        return $obj;
    }

    public function test_final_body_over_max_bytes_declines(): void
    {
        $config = $this->openConfig();
        $config->maxBodyBytes = 20; // base body already near the cap; the append cannot fit
        $base = self::base(['Content-Type' => 'text/html'], "<html><body>ok</body></html>");
        self::assertNull($this->decorate($base, ['bw' => ['ok']], null, $config));
    }

    public function test_decline_returns_the_untouched_base_object(): void
    {
        // On a decline the caller uses the base object unchanged (identity, not just equality).
        $base = self::base(['Content-Type' => 'application/json'], '{"ok":true}');
        $out = $this->decorate($base, ['bw' => ['ok']]);
        self::assertNull($out);
    }
}
