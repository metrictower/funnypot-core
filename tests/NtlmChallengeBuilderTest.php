<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Response\NtlmChallengeBuilder;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * FP-0389: unit tests for the NTLM Type-2 (CHALLENGE_MESSAGE) packer, in isolation (no Honeypot). An
 * independent in-test decoder parses the emitted bytes and asserts the structure + AV_PAIR round-trip
 * — the clean-room proof that the packer produces a spec-shaped Type-2 whose Target-Info leaks the
 * supplied AD names.
 */
final class NtlmChallengeBuilderTest extends TestCase
{
    private const NAMES = [
        'nbDomain' => 'NORTHWIND',
        'nbComputer' => 'EXCH01',
        'dnsDomain' => 'corp.northwind.com',
        'dnsComputer' => 'exch01.corp.northwind.com',
        'dnsTree' => 'northwind.com',
        'osMajor' => 10,
        'osMinor' => 0,
        'osBuild' => 17763,
    ];

    private const NONCE = "\x01\x23\x45\x67\x89\xab\xcd\xef";

    public function test_header_structure_signature_type_version(): void
    {
        $t2 = NtlmChallengeBuilder::buildType2(self::NAMES, self::NONCE);
        $d = $this->decode($t2);

        self::assertSame("NTLMSSP\x00", $d['sig'], 'signature');
        self::assertSame(2, $d['msgType'], 'MessageType = CHALLENGE');
        self::assertSame(self::NONCE, $d['challenge'], 'ServerChallenge echoes the nonce');
        self::assertSame(10, $d['ver']['maj'], 'Version major');
        self::assertSame(0, $d['ver']['min'], 'Version minor');
        self::assertSame(17763, $d['ver']['build'], 'Version build');
        self::assertSame(0x0F, $d['ntlmRevision'], 'NTLMRevision = W2K3');
        self::assertSame('NORTHWIND', $d['targetName'], 'TargetName = NetBIOS domain');
    }

    public function test_target_info_av_pairs_round_trip_the_ad_names(): void
    {
        $t2 = NtlmChallengeBuilder::buildType2(self::NAMES, self::NONCE);
        $d = $this->decode($t2);

        self::assertSame('NORTHWIND', $d['av'][0x0002] ?? null, 'MsvAvNbDomainName');
        self::assertSame('EXCH01', $d['av'][0x0001] ?? null, 'MsvAvNbComputerName');
        self::assertSame('corp.northwind.com', $d['av'][0x0004] ?? null, 'MsvAvDnsDomainName');
        self::assertSame('exch01.corp.northwind.com', $d['av'][0x0003] ?? null, 'MsvAvDnsComputerName');
        self::assertSame('northwind.com', $d['av'][0x0005] ?? null, 'MsvAvDnsTreeName');
        self::assertTrue($d['eol'], 'MsvAvEOL terminates the list');
        self::assertSame(0x0000, $d['lastId'], 'EOL is the last AV_PAIR');
    }

    public function test_header_value_is_ntlm_prefixed_base64(): void
    {
        $hv = NtlmChallengeBuilder::headerValue(self::NAMES, self::NONCE);
        self::assertStringStartsWith('NTLM ', $hv);
        $raw = base64_decode(substr($hv, 5), true);
        self::assertNotFalse($raw, 'remainder is valid base64');
        self::assertSame(NtlmChallengeBuilder::buildType2(self::NAMES, self::NONCE), $raw, 'decodes to the Type-2');
        // The serve-time header-splitting guard rejects CR/LF/NUL; base64 + the literal prefix carry none.
        self::assertSame(0, preg_match('/[\r\n\x00]/', $hv));
    }

    public function test_bad_nonce_length_is_normalized_not_fatal(): void
    {
        $short = NtlmChallengeBuilder::buildType2(self::NAMES, 'abc');     // 3 bytes
        $long = NtlmChallengeBuilder::buildType2(self::NAMES, str_repeat('Z', 40));
        self::assertSame("abc\x00\x00\x00\x00\x00", $this->decode($short)['challenge'], 'short nonce padded to 8');
        self::assertSame('ZZZZZZZZ', $this->decode($long)['challenge'], 'long nonce clipped to 8');
    }

    public function test_utf16le_interleaves_a_zero_byte(): void
    {
        $m = new ReflectionMethod(NtlmChallengeBuilder::class, 'utf16le');
        $m->setAccessible(true);
        $expected = '';
        foreach (str_split('EXCH01') as $ch) {
            $expected .= $ch . "\x00";
        }
        self::assertSame($expected, $m->invoke(null, 'EXCH01'));
    }

    // --- an independent Type-2 decoder (the clean-room round-trip proof) -----------------------------

    /** @return array<string,mixed> */
    private function decode(string $bytes): array
    {
        $sig = substr($bytes, 0, 8);
        $msgType = (int) unpack('V', substr($bytes, 8, 4))[1];
        $challenge = substr($bytes, 24, 8);
        $ti = unpack('vlen/vmax/Voff', substr($bytes, 40, 8));
        $ver = unpack('Cmaj/Cmin/vbuild', substr($bytes, 48, 4));
        $ntlmRevision = ord($bytes[55]);

        $tn = unpack('vlen/vmax/Voff', substr($bytes, 12, 8));
        $targetName = $this->fromUtf16le(substr($bytes, (int) $tn['off'], (int) $tn['len']));

        $av = [];
        $eol = false;
        $lastId = -1;
        $p = (int) $ti['off'];
        $end = $p + (int) $ti['len'];
        while ($p + 4 <= $end) {
            $id = (int) unpack('v', substr($bytes, $p, 2))[1];
            $len = (int) unpack('v', substr($bytes, $p + 2, 2))[1];
            $p += 4;
            $lastId = $id;
            if ($id === 0x0000) {
                $eol = true;
                break;
            }
            $av[$id] = $this->fromUtf16le(substr($bytes, $p, $len));
            $p += $len;
        }

        return [
            'sig' => $sig,
            'msgType' => $msgType,
            'challenge' => $challenge,
            'ver' => ['maj' => (int) $ver['maj'], 'min' => (int) $ver['min'], 'build' => (int) $ver['build']],
            'ntlmRevision' => $ntlmRevision,
            'targetName' => $targetName,
            'av' => $av,
            'eol' => $eol,
            'lastId' => $lastId,
        ];
    }

    /** UTF-16LE of ASCII back to ASCII: keep the low byte of each 2-byte unit. */
    private function fromUtf16le(string $s): string
    {
        $out = '';
        for ($i = 0; $i < strlen($s); $i += 2) {
            $out .= $s[$i];
        }

        return $out;
    }
}
