<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0561: NoSQL authentication-bypass → signed decoy-session mint. The decoy-session `mint` behavior with
 * `credential_bypass: nosql-operator` mints the signed cookie + the authored 302 on a NoSQL operator captured
 * on a credential field (username[$ne]= / {"username":{"$ne":null}}) — payloads whose empty/object values fail
 * the scalar-credential plausibility gate. The operator is RE-VALIDATED in the engine (not merely trusted from
 * the rule's match), minting is inert (fixed redirect, no reflection), and the whole thing is gated behind the
 * decoySessionKey kill switch so an unkeyed deploy never mints.
 */
final class NoSqlDecoySessionMintTest extends TestCase
{
    private const KEY = 'test-decoy-session-signing-key-0123456789';
    private const LOGIN_STUB = '<!doctype html><title>Sign in</title><form method="post"><input name="username"><input name="password"></form>';

    /** A NoSQL-bypass mint rule: captures the operator-on-credential-field into (?P<bypass>…). */
    private function nosqlRule(): array
    {
        return [
            'id' => 'decoy-nosql-mint-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 200,
            'match' => [
                ['in' => 'method', 'regex' => '^POST$'],
                ['in' => 'path', 'regex' => '^/api/auth$'],
                [
                    'in' => 'request',
                    'regex' => '(?P<bypass>(?:username|user|login|email|pass(?:word)?)(?:\[\s*\$|"\s*:\s*\{\s*"\s*\$)(?:ne|gte?|lte?|gt|lt|in|nin|regex|exists|where|or|nor|not)\b)',
                    'capture' => true,
                    'ci' => true,
                ],
            ],
            'response' => ['headers' => [], 'body' => self::LOGIN_STUB],
            'behavior' => 'decoy-session',
            'decoy-session' => [
                'mode' => 'mint',
                'cookie_name' => 'app_session',
                'cookie_path' => '/',
                'redirect' => '/dashboard',
                'credential_bypass' => 'nosql-operator',
            ],
        ];
    }

    private function emulator(?string $key = self::KEY): TemplateAttackEmulator
    {
        return new TemplateAttackEmulator([$this->nosqlRule()], [], null, null, [], null, $key);
    }

    private function post(TemplateAttackEmulator $em, string $body, array $headers = []): ?object
    {
        return $em->emulate(new RequestContext('POST', '/api/auth', '', $headers, $body));
    }

    public function test_form_operator_bypass_mints_signed_session(): void
    {
        $r = $this->post($this->emulator(), 'username[$ne]=&password[$ne]=');
        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertArrayHasKey('Set-Cookie', $r->headers, 'the bypass must mint a session cookie');
        self::assertStringContainsString('app_session=', $r->headers['Set-Cookie']);
        self::assertSame('/dashboard', $r->headers['Location'] ?? null, 'fixed authored redirect');
    }

    public function test_json_operator_bypass_mints_signed_session(): void
    {
        $r = $this->post($this->emulator(), '{"username":{"$ne":null},"password":{"$ne":null}}', ['Content-Type' => 'application/json']);
        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertStringContainsString('app_session=', (string) ($r->headers['Set-Cookie'] ?? ''));
    }

    /** THE KILL SWITCH: an unkeyed deploy never mints — no Set-Cookie, no 302 (serves the base login page). */
    public function test_unkeyed_deploy_never_mints(): void
    {
        $r = $this->post($this->emulator(null), 'username[$ne]=&password[$ne]=');
        if ($r !== null) {
            self::assertArrayNotHasKey('Set-Cookie', $r->headers, 'unkeyed must not mint a cookie');
            self::assertNotSame(302, $r->status, 'unkeyed must not redirect');
        } else {
            self::assertNull($r);
        }
    }

    /** Defense-in-depth: a rule that opts into the bypass but whose capture is NOT an operator never mints. */
    public function test_engine_revalidates_the_operator_and_declines_benign_capture(): void
    {
        $rule = $this->nosqlRule();
        // A loose capture that grabs a benign scalar credential (no NoSQL operator) — the engine's own
        // re-validation must still refuse to mint.
        $rule['match'][2]['regex'] = '(?P<bypass>username=[^&]*)';
        $em = new TemplateAttackEmulator([$rule], [], null, null, [], null, self::KEY);
        $r = $em->emulate(new RequestContext('POST', '/api/auth', '', [], 'username=alice&password=hunter2'));
        if ($r !== null) {
            self::assertArrayNotHasKey('Set-Cookie', $r->headers, 'no operator evidence ⇒ no mint');
            self::assertNotSame(302, $r->status);
        } else {
            self::assertNull($r);
        }
    }

    public function test_operator_bytes_are_never_reflected(): void
    {
        $r = $this->post($this->emulator(), 'username[$ne]=CANARYVALUE&password[$ne]=CANARYVALUE');
        self::assertNotNull($r);
        self::assertStringNotContainsString('CANARYVALUE', (string) ($r->headers['Set-Cookie'] ?? ''));
        self::assertStringNotContainsString('CANARYVALUE', (string) ($r->headers['Location'] ?? ''));
        self::assertStringNotContainsString('CANARYVALUE', (string) $r->body);
    }

    public function test_crafted_redirect_field_cannot_steer_location(): void
    {
        // A $ne operator on a 'redirect'-looking field must not match (not a credential field); and even a
        // body carrying a redirect value never changes the authored Location.
        $r = $this->post($this->emulator(), 'username[$ne]=&password[$ne]=&redirect=https%3A%2F%2Fevil.example%2Fpwn');
        self::assertNotNull($r);
        self::assertSame('/dashboard', $r->headers['Location'] ?? null, 'Location is the authored literal, never a submitted value');
    }

    public function test_cookie_round_trips_within_a_deploy(): void
    {
        // Deterministic signed cookie for a keyed deploy (the mint is reproducible for the same request).
        $a = (string) ($this->post($this->emulator(), 'username[$ne]=&password[$ne]=')->headers['Set-Cookie'] ?? '');
        $b = (string) ($this->post($this->emulator(), 'username[$ne]=&password[$ne]=')->headers['Set-Cookie'] ?? '');
        self::assertNotSame('', $a);
        self::assertSame($a, $b);
    }
}
