<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0572: NoSQL auth-bypass -> decoy-session MINT consumer template (attack-nosql-signin-mint,
 * POST /api/signin, uses the FP-0561 engine mechanism). A keyed deploy mints a signed session (302 +
 * Set-Cookie) on a NoSQL operator captured on a credential field; an unkeyed deploy is byte-identical
 * to today (the 121-nosql-operator reclassify for an operator POST, a plain 404 for a benign POST).
 */
final class NoSqlSigninMintTest extends TestCase
{
    private const KEY = 'test-decoy-session-signing-key-0123456789';
    private const OPERATOR = '{"email":{"$ne":null},"password":{"$ne":null}}';
    /** The exact bytes 121-nosql-operator reclassify serves for an operator POST (unkeyed byte-identity). */
    private const BASE_BODY = "{\"data\":[],\"total\":0}\n";

    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(?string $key): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,
            personaSeed: static fn (RequestContext $r): string => 'fixed',
            attackEmulation: true,
            deploySeed: 'fixed',
            decoySessionKey: $key
        );

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function post(Honeypot $hp, string $body): ?object
    {
        return $hp->respond(new RequestContext('POST', '/api/signin', '', ['Content-Type' => 'application/json'], $body, 'x.test'));
    }

    public function test_keyed_deploy_mints_a_session_on_a_nosql_operator(): void
    {
        $r = $this->post($this->engine(self::KEY), self::OPERATOR);
        self::assertNotNull($r);
        self::assertSame(302, $r->status, 'the bypass mints a 302 redirect');
        $loc = $r->headers['Location'] ?? $r->headers['location'] ?? '';
        self::assertSame('/account', $loc, 'redirects to the dashboard (rooted-relative, no open redirect)');
        $cookie = $r->headers['Set-Cookie'] ?? $r->headers['set-cookie'] ?? '';
        self::assertStringContainsString('connect.sid=', $cookie, 'issues a session cookie (the 2nd Artemis signal)');
    }

    public function test_unkeyed_deploy_is_byte_identical_to_the_121_reclassify(): void
    {
        $r = $this->post($this->engine(null), self::OPERATOR);
        self::assertNotNull($r);
        self::assertSame(200, $r->status, 'unkeyed never mints — serves the base JSON');
        self::assertSame(self::BASE_BODY, $r->body, 'base body is byte-identical to the 121-nosql-operator reclassify');
        $ct = $r->headers['Content-Type'] ?? $r->headers['content-type'] ?? '';
        self::assertSame('application/json; charset=utf-8', $ct);
        $cookie = $r->headers['Set-Cookie'] ?? $r->headers['set-cookie'] ?? '';
        self::assertSame('', $cookie, 'unkeyed issues NO cookie');
    }

    public function test_benign_and_scalar_credentials_do_not_mint(): void
    {
        $keyed = $this->engine(self::KEY);
        // A benign scalar login (no operator) does not match -> plain 404, unchanged.
        self::assertNull($this->post($keyed, '{"email":"a@b.c","password":"secret"}'), 'benign scalar login -> 404');
        // A scalar value that merely CONTAINS "ne" is not an operator -> no false mint.
        self::assertNull($this->post($keyed, '{"email":"a@b.c","password":"nextpass"}'), 'scalar "ne" text is not an operator');
    }

    public function test_no_attacker_byte_is_reflected(): void
    {
        $canary = 'ZZSIGNINZZ';
        $body = '{"email":{"$ne":"' . $canary . '"},"password":{"$ne":null}}';
        foreach ([self::KEY, null] as $key) {
            $r = $this->post($this->engine($key), $body);
            self::assertNotNull($r);
            self::assertStringNotContainsString($canary, (string) $r->body, 'operator bytes never reflected in the body');
            foreach ($r->headers as $v) {
                self::assertStringNotContainsString($canary, (string) $v, 'operator bytes never reflected in a header');
            }
        }
    }
}
