<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Attack\CannedData;
use PHPUnit\Framework\TestCase;

/**
 * The shared canned attack markers are served bytes, so they must carry no brand tell and every
 * fabricated "secret" must be inert (crypt of no password, a key that decodes to nothing).
 */
final class CannedDataTest extends TestCase
{
    public function test_no_canned_marker_carries_a_brand_tell(): void
    {
        foreach ([
            'PASSWD' => CannedData::PASSWD,
            'SHADOW' => CannedData::SHADOW,
            'GROUP' => CannedData::GROUP,
            'HOSTNAME' => CannedData::HOSTNAME,
            'SSH_PRIVATE_KEY' => CannedData::SSH_PRIVATE_KEY,
            'ENVIRON' => CannedData::ENVIRON,
            'WININI' => CannedData::WININI,
            'UID' => CannedData::UID,
        ] as $name => $value) {
            self::assertStringNotContainsStringIgnoringCase('fnpot', $value, "{$name} leaks a brand tell");
            self::assertStringNotContainsStringIgnoringCase('funnypot', $value, "{$name} leaks a brand tell");
        }
    }

    public function test_shadow_root_hash_is_sha512_crypt_shaped(): void
    {
        // $6$<salt up to 16>$<86-char hash>, crypt base64 alphabet (./0-9A-Za-z). A realistic
        // shape so an LFI reader sees a normal shadow line, not an all-zero canary.
        self::assertSame(
            1,
            preg_match(
                '#^root:\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}:#',
                CannedData::SHADOW
            ),
            'root shadow entry must look like a real sha512-crypt hash'
        );
        // Not the old all-zero hash, and the aging-field layout LFI templates key on is preserved.
        self::assertStringNotContainsString('$000000', CannedData::SHADOW);
        self::assertStringContainsString(':0:99999:7:::', CannedData::SHADOW);
    }

    public function test_hostname_is_a_single_plausible_line(): void
    {
        self::assertSame(1, preg_match('/^[a-z0-9][a-z0-9.-]{1,62}\n$/', CannedData::HOSTNAME));
    }

    public function test_ssh_private_key_is_a_valid_but_inert_pem(): void
    {
        self::assertStringStartsWith('-----BEGIN OPENSSH PRIVATE KEY-----', CannedData::SSH_PRIVATE_KEY);
        self::assertStringContainsString('-----END OPENSSH PRIVATE KEY-----', CannedData::SSH_PRIVATE_KEY);

        preg_match(
            '/-----BEGIN OPENSSH PRIVATE KEY-----\n(.*)\n-----END/s',
            CannedData::SSH_PRIVATE_KEY,
            $m
        );
        $blob = base64_decode(str_replace("\n", '', $m[1]), true);
        self::assertNotFalse($blob, 'the key body must be well-formed base64');
        // A real OpenSSH private key blob begins with this magic; ours must NOT, so it is a
        // structurally invalid, non-functional key that authenticates nowhere.
        self::assertStringStartsNotWith("openssh-key-v1\0", $blob);
    }
}
