<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use Closure;
use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Reaction\ParamIntent;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end wiring across both engine phases against a controlled store: the intent attaches at
 * classify only when the reflecting-decoy gate is open, never changes classification/detection, and
 * decorates ONLY on the respond() facade (which threads the live request) — never on the position-blind
 * port, and never on an embedded origin. Every off-path yields byte-identical-to-baseline output.
 */
final class ParamReactionIntegrationTest extends TestCase
{
    private static function vouch(): Closure
    {
        return static function (RequestContext $r, string $class): bool { return true; };
    }

    /** @return array<string,mixed> */
    private static function index(): array
    {
        return [
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                'html-t' => ['sev' => 'medium', 'tags' => [], 'name' => 'HTML'],
                'text-t' => ['sev' => 'medium', 'tags' => [], 'name' => 'TEXT'],
                'x-t' => ['sev' => 'medium', 'tags' => [], 'name' => 'X'],
                'root-t' => ['sev' => 'info', 'tags' => [], 'name' => 'ROOT'],
            ],
            'routes' => [
                'GET /shop' => ['b' => [[
                    's' => 200, 'bw' => ['<html', 'Welcome', '</body>'], 'h' => ['Content-Type' => 'text/html'],
                    'pid' => 'shop', 'sev' => 'medium', 'sig' => 0, 't' => ['html-t'],
                ]]],
                'GET /notes.txt' => ['b' => [[
                    's' => 200, 'bw' => ['note one'], 'h' => ['Content-Type' => 'text/plain'],
                    'pid' => 'notes', 'sev' => 'medium', 'sig' => 0, 't' => ['text-t'],
                ]]],
                'GET /exact.txt' => ['b' => [[
                    's' => 200, 'bw' => ['EXACTBODY'], 'x' => true, 'h' => ['Content-Type' => 'text/plain'],
                    'pid' => 'exact', 'sev' => 'medium', 'sig' => 0, 't' => ['x-t'],
                ]]],
                'GET /' => ['b' => [[
                    's' => 200, 'bw' => ['<html', 'Home', '</body>'], 'h' => ['Content-Type' => 'text/html'],
                    'pid' => 'home', 'sev' => 'info', 'sig' => 1, 't' => ['root-t'],
                ]]],
            ],
        ];
    }

    private function engine(bool $isolated = true, bool $paramReactivity = true, bool $authorized = true, array $reflectClasses = []): Honeypot
    {
        $config = new Config(
            'respond',                                                  // mode
            static function (RequestContext $r): bool { return true; }, // gate (open)
            'matched-only', null, 'coherent',
            Style::REALISTIC,                                           // responseStyle (MINIMAL is gated out)
            'high', 65536, 0, 0,
            false                                                       // attackEmulation off (isolate the route path)
        );
        $config->isolatedOrigin = $isolated;
        $config->paramReactivity = $paramReactivity;
        $config->reflectorAuthorizer = $authorized ? self::vouch() : null;
        $config->reflectClasses = $reflectClasses;
        // A root/homepage probe signature so the sig=1 entry can serve when needed.
        $config->probeSignature = static function (RequestContext $r): bool { return true; };

        return new Honeypot(new PhpArrayStore(self::index()), $config);
    }

    private static function req(string $path, string $query = ''): RequestContext
    {
        return new RequestContext('GET', $path, $query, [], null, 'shop.example');
    }

    // --- classify: intent attaches only under the open gate, never changes the verdict shape -------

    public function test_intent_attaches_without_changing_classification_or_detection(): void
    {
        $engine = $this->engine();
        $withIntent = $engine->classify(self::req('/shop', 'file=../../etc/passwd'), SiteProfile::empty());
        $noQuery = $engine->classify(self::req('/shop'), SiteProfile::empty());

        self::assertSame(Verdict::SCANNER_PROBE, $withIntent->classification);
        self::assertInstanceOf(FakeHandle::class, $withIntent->fakeHandle);
        self::assertInstanceOf(ParamIntent::class, $withIntent->fakeHandle->paramIntent);
        self::assertSame(ParamIntent::KIND_FILE_READ, $withIntent->fakeHandle->paramIntent->kind);

        // Everything except the handle's optional intent is identical to the no-query verdict.
        self::assertSame($noQuery->classification, $withIntent->classification);
        self::assertSame($noQuery->detection->templateIds(), $withIntent->detection->templateIds());
        self::assertSame($noQuery->severity, $withIntent->severity);
        self::assertSame($noQuery->anomaly, $withIntent->anomaly);
        self::assertEquals($noQuery->signals, $withIntent->signals);
    }

    /**
     * @dataProvider noIntentProvider
     */
    public function test_no_intent_attaches_and_handle_is_byte_identical(string $why, Honeypot $engine, RequestContext $r): void
    {
        $baseline = $this->engine()->classify(self::req('/shop'), SiteProfile::empty());
        $verdict = $engine->classify($r, SiteProfile::empty());

        self::assertNotNull($verdict->fakeHandle, $why);
        self::assertNull($verdict->fakeHandle->paramIntent, $why);
        self::assertSame($baseline->fakeHandle->toArray(), $verdict->fakeHandle->toArray(), $why);
    }

    /** @return iterable<string,array{0:string,1:Honeypot,2:RequestContext}> */
    public function noIntentProvider(): iterable
    {
        yield 'ordinary page=2' => ['page=2 is not path-like', $this->engine(), self::req('/shop', 'page=2')];
        yield 'reactivity off' => ['paramReactivity=false', $this->engine(true, false), self::req('/shop', 'file=../x')];
        yield 'embedded origin' => ['isolatedOrigin=false', $this->engine(false), self::req('/shop', 'file=../x')];
        yield 'class subtracted' => ['param-reaction disabled', $this->engine(true, true, true, ['param-reaction' => false]), self::req('/shop', 'file=../x')];
        yield 'no authorizer' => ['no evidence', $this->engine(true, true, false), self::req('/shop', 'file=../x')];
    }

    public function test_root_entry_never_carries_an_intent(): void
    {
        $verdict = $this->engine()->classify(self::req('/', 'q=hello'), SiteProfile::empty());
        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertNull($verdict->fakeHandle->paramIntent, 'a root/homepage entry must not react');
    }

    public function test_real_route_and_store_miss_carry_no_handle(): void
    {
        $engine = $this->engine();

        $profile = new SiteProfile([], static function (string $method, string $path): bool {
            return $method === 'GET' && $path === '/shop';
        });
        $real = $engine->classify(self::req('/shop', 'file=../x'), $profile);
        self::assertSame(Verdict::CLEAN, $real->classification);
        self::assertNull($real->fakeHandle);

        $miss = $engine->classify(self::req('/nonexistent', 'file=../x'), SiteProfile::empty());
        self::assertNull($miss->fakeHandle);
    }

    // --- serve: respond() decorates, the port and embedded origins do not ------------------------

    public function test_respond_decorates_html_and_text_routes(): void
    {
        $engine = $this->engine();

        $html = $engine->respond(self::req('/shop', 'file=../../etc/passwd'));
        self::assertNotNull($html);
        self::assertStringContainsString('file-preview', $html->body);
        self::assertSame('text/html', $html->headers['Content-Type']);

        $text = $engine->respond(self::req('/notes.txt', 'q=hello'));
        self::assertNotNull($text);
        self::assertStringContainsString('search results for:', $text->body);
        self::assertSame('text/plain', $text->headers['Content-Type']);
    }

    public function test_respond_does_not_react_on_an_exclusive_bundle(): void
    {
        $engine = $this->engine();
        $out = $engine->respond(self::req('/exact.txt', 'q=hello'));
        self::assertNotNull($out);
        self::assertSame('EXACTBODY', $out->body, 'an x bundle must serve byte-identical base bytes');
    }

    public function test_position_blind_port_never_reacts(): void
    {
        $engine = $this->engine();
        $verdict = $engine->classify(self::req('/shop', 'file=../../etc/passwd'), SiteProfile::empty());
        self::assertInstanceOf(ParamIntent::class, $verdict->fakeHandle->paramIntent);

        $port = $engine->synthesize($verdict, SiteProfile::empty(), 'seed');
        self::assertNotNull($port);
        self::assertStringNotContainsString('file-preview', $port->body, 'the port carries no request => no reaction');

        // And the same probe DOES react through the facade.
        self::assertStringContainsString('file-preview', (string) $engine->respond(self::req('/shop', 'file=../../etc/passwd'))->body);
    }

    public function test_embedded_origin_serves_the_undecorated_base(): void
    {
        // B2: an embedded host can never echo, whatever paramReactivity or the class map say.
        $embedded = $this->engine(false, true, true);
        $out = $embedded->respond(self::req('/shop', 'q=<script>alert(1)</script>'));
        self::assertNotNull($out);
        self::assertStringNotContainsString('search-results', $out->body);
        self::assertStringNotContainsString('<script>alert(1)', $out->body);
    }

    public function test_config_off_serves_byte_identical_bodies(): void
    {
        $off = $this->engine(true, false);
        $withQuery = $off->respond(self::req('/shop', 'q=hello'));
        $noQuery = $off->respond(self::req('/shop'));

        self::assertNotNull($withQuery);
        self::assertNotNull($noQuery);
        self::assertSame($noQuery->body, $withQuery->body, 'with the feature off, a query cannot change served bytes');
    }
}
