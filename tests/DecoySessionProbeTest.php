<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\DecoySessionProbe;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The honeytoken-retrieval probe (sibling of OastProbeTest): a request presenting a valid, minted
 * `s=1` decoy-session cookie means the client walked the mock-auth trap and is pulling loot. A valid
 * `s=1` is unforgeable (HMAC), so the probe is high-confidence; it is name-agnostic (any cookie
 * value in the header), side-effect-free, and disabled by an empty key.
 */
final class DecoySessionProbeTest extends TestCase
{
    private const KEY = 'S3cr3t-Decoy-Signing-Key-must-never-leak';

    /** The name=value pair a browser sends back, built from a Set-Cookie of the given payload class. */
    private function cookiePair(string $payload, string $name = 'phpMyAdmin'): string
    {
        $setCookie = (new Honeytoken(self::KEY))->cookie($name, $payload, '/phpmyadmin');
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    private function req(?string $cookieHeader): RequestContext
    {
        $headers = $cookieHeader === null ? [] : ['Cookie' => $cookieHeader];

        return new RequestContext('GET', '/phpmyadmin/index.php', 'table=secrets', $headers);
    }

    public function test_valid_s1_cookie_is_authenticated(): void
    {
        self::assertTrue(DecoySessionProbe::authenticated($this->req($this->cookiePair('s=1')), self::KEY));
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

    public function test_validly_signed_s0_is_not_authenticated(): void
    {
        // A validly-signed pre-auth marker (s=0) must NOT count — a different payload class, not a
        // weaker s=1.
        self::assertFalse(DecoySessionProbe::authenticated($this->req($this->cookiePair('s=0')), self::KEY));
    }

    public function test_empty_key_disables_the_probe(): void
    {
        // Even a real s=1 cookie yields false when no decoy-session key is configured.
        self::assertFalse(DecoySessionProbe::authenticated($this->req($this->cookiePair('s=1')), ''));
    }

    public function test_wrong_key_is_not_authenticated(): void
    {
        // A cookie minted under a different key does not verify — the signature is unforgeable.
        self::assertFalse(DecoySessionProbe::authenticated($this->req($this->cookiePair('s=1')), 'a-different-key'));
    }

    public function test_name_agnostic_matches_any_cookie_in_the_header(): void
    {
        // The minted session sits under an arbitrary cookie name, alongside unrelated cookies. The
        // probe inspects every value, so it is found regardless of name or position.
        $header = 'other=abc; some_other_panel=' . substr($this->cookiePair('s=1', 'some_other_panel'), strlen('some_other_panel=')) . '; tracking=xyz';
        self::assertTrue(DecoySessionProbe::authenticated($this->req($header), self::KEY));
    }

    public function test_case_insensitive_cookie_header_name(): void
    {
        self::assertTrue(DecoySessionProbe::authenticated(
            new RequestContext('GET', '/phpmyadmin/index.php', '', ['cookie' => $this->cookiePair('s=1')]),
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
