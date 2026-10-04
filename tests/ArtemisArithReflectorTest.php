<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0386: the dynamic arithmetic command-injection reflector (attack-cmdi-arith). CERT-Polska Artemis
 * injects `echo {left}$(({a}*{b})){right}` and confirms ONLY if the body carries `{left}{a*b}{right}`.
 * The decoy computes a*b (Support\SafeArithmetic, zero-exec) and reflects that marker — but ONLY from an
 * isolated origin with the request authorized (it echoes attacker tokens, so it is reflector-gated).
 */
final class ArtemisArithReflectorTest extends TestCase
{
    /** @var array<string,mixed> */
    private static function index(): array
    {
        return require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    }

    private function engine(bool $isolated, bool $authorized = true): Honeypot
    {
        $cfg = new Config('respond', null, 'matched-only', null, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $cfg->isolatedOrigin = $isolated;
        $cfg->attackEmulation = true;
        $cfg->reflectorAuthorizer = static function (RequestContext $r, string $class) use ($authorized): bool {
            return $authorized;
        };

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    private function probe(string $left, int $a, int $b, string $right): RequestContext
    {
        $q = 'q=echo%20' . $left . '%24%28%28' . $a . '%2a' . $b . '%29%29' . $right;

        return new RequestContext('GET', '/x', $q, [], null, 'x.test');
    }

    private function body(?object $resp): string
    {
        return $resp !== null ? (string) $resp->body : '';
    }

    public function test_isolated_origin_reflects_the_computed_marker(): void
    {
        $resp = $this->engine(true)->respond($this->probe('abcdef1234', 1234, 5678, 'fedcba99'), SiteProfile::empty(), 's');
        $marker = 'abcdef1234' . (1234 * 5678) . 'fedcba99';
        self::assertStringContainsString($marker, $this->body($resp), 'the Artemis confirmation marker (left+product+right) must be present');
    }

    public function test_product_is_actually_computed_not_echoed(): void
    {
        // A static echo would return the literal payload; only a real eval forms left+product+right.
        $resp = $this->engine(true)->respond($this->probe('aa11bb22', 4321, 8765, 'cc33dd44'), SiteProfile::empty(), 's');
        $b = $this->body($resp);
        self::assertStringContainsString('aa11bb22' . (4321 * 8765) . 'cc33dd44', $b);
        self::assertStringNotContainsString('4321*8765', $b, 'the raw a*b expression must not be echoed verbatim');
    }

    public function test_embedded_host_suppresses_the_reflection(): void
    {
        // isolatedOrigin=false (an embedded Laravel/WordPress host) must never become an RCE oracle.
        $resp = $this->engine(false)->respond($this->probe('abcdef1234', 1234, 5678, 'fedcba99'), SiteProfile::empty(), 's');
        self::assertStringNotContainsString('abcdef1234' . (1234 * 5678), $this->body($resp));
    }

    public function test_unauthorized_request_suppresses_the_reflection(): void
    {
        $resp = $this->engine(true, false)->respond($this->probe('abcdef1234', 1234, 5678, 'fedcba99'), SiteProfile::empty(), 's');
        self::assertStringNotContainsString('abcdef1234' . (1234 * 5678), $this->body($resp));
    }

    public function test_non_matching_payloads_do_not_form_a_marker(): void
    {
        $e = $this->engine(true);
        // No '*' (not a product expansion): the grammar requires d*d, so no marker forms.
        $noMul = new RequestContext('GET', '/x', 'q=echo%20abcdef1234%24%28%281234%29%29fedcba99', [], null, 'x.test');
        self::assertStringNotContainsString('1234fedcba99', $this->body($e->respond($noMul, SiteProfile::empty(), 's')));
        // FP-0466: the anchor charset is now [A-Za-z0-9] (was hex), so a non-hex alnum anchor like
        // `zzzzzz` is INTENTIONALLY valid. The remaining non-match guard is the min-length boundary: an
        // anchor of <3 alnum chars immediately before `$((` declines (left requires {3,16}).
        $tooShort = new RequestContext('GET', '/x', 'q=echo%20xy%24%28%281234%2a5678%29%29fedcba99', [], null, 'x.test');
        self::assertStringNotContainsString((string) (1234 * 5678) . 'fedcba99', $this->body($e->respond($tooShort, SiteProfile::empty(), 's')));
    }

    public function test_reflected_tokens_are_alnum_only_no_markup(): void
    {
        $resp = $this->engine(true)->respond($this->probe('abcdef1234', 1111, 2222, 'fedcba99'), SiteProfile::empty(), 's');
        $b = $this->body($resp);
        self::assertStringNotContainsString('<', $b, 'no attacker markup can reach the body (hex-only tokens)');
        self::assertStringNotContainsString('>', $b);
    }
}
