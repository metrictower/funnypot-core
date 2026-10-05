<?php

declare(strict_types=1);

namespace Funnypot\Core\Response;

/**
 * A pure, zero-dependency packer for an NTLM (MS-NLMP) Type-2 CHALLENGE_MESSAGE, the token a real
 * Windows/Exchange server returns in `WWW-Authenticate: NTLM <base64>` when a client sends a Type-1
 * Negotiate. Its Target-Info AV_PAIRs carry the server's Active-Directory names, so emitting one is a
 * deliberate, synthetic information-leak used by the Exchange/IIS decoy.
 *
 * Clean-room from the public MS-NLMP spec: every multi-byte integer is little-endian, ASCII is widened
 * to UTF-16LE by interleaving a zero byte (exact for ASCII AD names), and nothing here depends on
 * ext-mbstring/iconv. The builder is total — it never throws on normal input and normalizes a wrong
 * nonce length — so the only-upgrade-a-404 invariant can live entirely in the caller.
 */
final class NtlmChallengeBuilder
{
    // A representative real Exchange challenge: UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN |
    // TARGET_TYPE_DOMAIN | TARGET_INFO | VERSION. TARGET_INFO set is what makes the scanner read the
    // AV_PAIR block (the leak); VERSION set makes the 8-byte Version field meaningful.
    private const NEGOTIATE_FLAGS = 0x02818205;

    // The payload (TargetName then TargetInfo) always begins right after the fixed 56-byte header,
    // because the Version field is present.
    private const PAYLOAD_OFFSET = 56;

    // AV_PAIR type ids, emitted in this order then terminated by MsvAvEOL.
    private const AV_NB_DOMAIN = 0x0002;
    private const AV_NB_COMPUTER = 0x0001;
    private const AV_DNS_DOMAIN = 0x0004;
    private const AV_DNS_COMPUTER = 0x0003;
    private const AV_DNS_TREE = 0x0005;
    private const AV_EOL = 0x0000;

    /**
     * The raw Type-2 bytes. Keys of $names: nbDomain, nbComputer, dnsDomain, dnsComputer, dnsTree
     * (all ASCII strings), osMajor, osMinor, osBuild (ints for the Version field). $nonce8 is the
     * 8-byte ServerChallenge; a wrong length is normalized (padded/clipped), never fatal.
     *
     * @param array<string,mixed> $names
     */
    public static function buildType2(array $names, string $nonce8): string
    {
        if (strlen($nonce8) !== 8) {
            $nonce8 = substr(str_pad($nonce8, 8, "\x00"), 0, 8);
        }

        $nbDomain = (string) ($names['nbDomain'] ?? '');

        // TargetName is the NetBIOS domain in UTF-16LE (what real servers set).
        $targetName = self::utf16le($nbDomain);

        // The Target-Info AV_PAIR list — the leak — in the spec's order, EOL last.
        $targetInfo = self::avPair(self::AV_NB_DOMAIN, self::utf16le($nbDomain))
            . self::avPair(self::AV_NB_COMPUTER, self::utf16le((string) ($names['nbComputer'] ?? '')))
            . self::avPair(self::AV_DNS_DOMAIN, self::utf16le((string) ($names['dnsDomain'] ?? '')))
            . self::avPair(self::AV_DNS_COMPUTER, self::utf16le((string) ($names['dnsComputer'] ?? '')))
            . self::avPair(self::AV_DNS_TREE, self::utf16le((string) ($names['dnsTree'] ?? '')))
            . pack('vv', self::AV_EOL, 0);

        $tnLen = strlen($targetName);
        $tiLen = strlen($targetInfo);
        $tnOff = self::PAYLOAD_OFFSET;
        $tiOff = self::PAYLOAD_OFFSET + $tnLen;

        return pack('a8', "NTLMSSP\x00")                                   // Signature
            . pack('V', 2)                                                 // MessageType = CHALLENGE
            . pack('vvV', $tnLen, $tnLen, $tnOff)                          // TargetName security buffer
            . pack('V', self::NEGOTIATE_FLAGS)                             // NegotiateFlags
            . $nonce8                                                      // ServerChallenge
            . pack('x8')                                                   // Reserved
            . pack('vvV', $tiLen, $tiLen, $tiOff)                          // TargetInfo security buffer
            . pack(
                'CCvx3C',
                (int) ($names['osMajor'] ?? 10) & 0xFF,
                (int) ($names['osMinor'] ?? 0) & 0xFF,
                (int) ($names['osBuild'] ?? 0) & 0xFFFF,
                0x0F                                                       // NTLMRevision = NTLMSSP_REVISION_W2K3
            )
            . $targetName
            . $targetInfo;
    }

    /**
     * The ready-to-serve header value: `NTLM ` + base64 of the Type-2. base64 + the literal prefix
     * carry no CR/LF/NUL, so the value always clears the response header-splitting guard.
     *
     * @param array<string,mixed> $names
     */
    public static function headerValue(array $names, string $nonce8): string
    {
        return 'NTLM ' . base64_encode(self::buildType2($names, $nonce8));
    }

    /** One AV_PAIR: `AvId`, `AvLen` (byte length of the value), then the value. */
    private static function avPair(int $avId, string $valUtf16le): string
    {
        return pack('vv', $avId, strlen($valUtf16le)) . $valUtf16le;
    }

    /** ASCII -> UTF-16LE by interleaving a zero byte after each byte. Exact for ASCII; no mbstring. */
    private static function utf16le(string $ascii): string
    {
        $out = '';
        $len = strlen($ascii);
        for ($i = 0; $i < $len; $i++) {
            $out .= $ascii[$i] . "\x00";
        }

        return $out;
    }
}
