<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Behavior\DecoySessionPayloads;
use Funnypot\Core\DecoySessionProbe;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The honeytoken-retrieval probe (sibling of OastProbeTest): a request presenting a valid, minted
 * authenticated decoy-session cookie means the client walked the mock-auth trap and is pulling loot.
 * The token is unforgeable (HMAC), so the probe is high-confidence; it is name-agnostic (any cookie
 * value in the header), side-effect-free, disabled by an empty key, and (FP-0296) seed-scoped — a
 * token from a different deploy seed fails closed under the same key.
 */
final class DecoySessionProbeTest extends TestCase
{
    private const KEY = 'S3cr3t-Decoy-Signing-Key-must-never-leak';

    private const SEED_A = 101;

    private const SEED_B = 202;

    /** The name=value pair a browser sends back for a minted cookie at the given seed/class. */
    private function mintedPair(?int $seed, string $name = 'phpMyAdmin', bool $preAuth = false): string
    {
        $session = new DecoySession(self::KEY, $seed);
        $setCookie = $preAuth ? $session->preAuthCookie($name, '/phpmyadmin') : $session->mintCookie($name, '/phpmyadmin');
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    /** A raw name=value pair carrying an arbitrary hand-signed payload (legacy/forged cases). */
    private function signedPair(string $payload, string $key = self::KEY, string $name = 'phpMyAdmin'): string
    {
        $setCookie = (new Honeytoken($key))->cookie($name, $payload, '/phpmyadmin');
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    private function req(?string $cookieHeader): RequestContext
    {
        $headers = $cookieHeader === null ? [] : ['Cookie' => $cookieHeader];

        return new RequestContext('GET', '/phpmyadmin/index.php', 'table=secrets', $headers);
    }

    public function test_valid_authenticated_cookie_is_authenticated(): void
    {
        // Default probe seed is null -> seed 0, so mint at seed 0 to round-trip.
        self::assertTrue(DecoySessionProbe::authenticated($this->req($this->mintedPair(0)), self::KEY));
    }

    public function test_absent_cookie_is_not_authenticated(): void
    {
        self::assertFalse(DecoySessionProbe::authenticated($this->req(null), self::KEY));
        self::assertFalse(DecoySessionProbe::authenticated($this->req(''), self::KEY));
    }

    public function test_garbage_cookie_is_not_authenticated(): void
    {
        self::assertFalse(DecoySessionProbe::authenticated($this->req('phpMyAdmin=nonsense-not-signed'), self::KEY));
    }

    public function test_validly_signed_pre_auth_is_not_authenticated(): void
    {
        // A validly-signed pre-auth marker must NOT count — a different payload class.
        self::assertFalse(DecoySessionProbe::authenticated($this->req($this->mintedPair(0, 'phpMyAdmin', true)), self::KEY));
    }

    public function test_legacy_literal_s1_is_not_authenticated(): void
    {
        // The retired fleet-constant token verifies under the key but is not seed 0's authenticated text.
        self::assertFalse(DecoySessionProbe::authenticated($this->req($this->signedPair('s=1')), self::KEY, 0));
    }

    public function test_cross_seed_token_fails_closed_under_the_same_key(): void
    {
        self::assertNotSame(
            DecoySessionPayloads::authenticated(self::SEED_A),
            DecoySessionPayloads::authenticated(self::SEED_B)
        );
        $tokenA = $this->mintedPair(self::SEED_A);
        // Seed A's own probe accepts it; seed B's rejects it.
        self::assertTrue(DecoySessionProbe::authenticated($this->req($tokenA), self::KEY, self::SEED_A));
        self::assertFalse(DecoySessionProbe::authenticated($this->req($tokenA), self::KEY, self::SEED_B));
    }

    public function test_empty_key_disables_the_probe(): void
    {
        // Even a real authenticated cookie yields false when no decoy-session key is configured.
        self::assertFalse(DecoySessionProbe::authenticated($this->req($this->mintedPair(0)), ''));
    }

    public function test_wrong_key_is_not_authenticated(): void
    {
        // A cookie minted under a different key does not verify — the signature is unforgeable.
        self::assertFalse(DecoySessionProbe::authenticated($this->req($this->mintedPair(0)), 'a-different-key'));
    }

    public function test_name_agnostic_matches_any_cookie_in_the_header(): void
    {
        // The minted session sits under an arbitrary cookie name, alongside unrelated cookies. The
        // probe inspects every value, so it is found regardless of name or position.
        $sessionPair = $this->mintedPair(0, 'some_other_panel');
        $value = substr($sessionPair, strlen('some_other_panel='));
        $header = 'other=abc; some_other_panel=' . $value . '; tracking=xyz';
        self::assertTrue(DecoySessionProbe::authenticated($this->req($header), self::KEY));
    }

    public function test_case_insensitive_cookie_header_name(): void
    {
        self::assertTrue(DecoySessionProbe::authenticated(
            new RequestContext('GET', '/phpmyadmin/index.php', '', ['cookie' => $this->mintedPair(0)]),
            self::KEY
        ));
    }

    public function test_detect_path_source_has_no_network_primitive(): void
    {
        $needles = [
            'fsockopen', 'curl_', 'file_get_contents', 'fopen', 'stream_socket',
            'gethostby', 'dns_get_record', 'checkdnsrr', 'socket_create',
        ];
        $src = file_get_contents(__DIR__ . '/../src/DecoySessionProbe.php');
        self::assertNotFalse($src);
        foreach ($needles as $needle) {
            self::assertStringNotContainsString($needle, $src, "DecoySessionProbe must not reference {$needle}");
        }
    }
}
