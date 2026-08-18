<?php

declare(strict_types=1);

namespace Funnypot\Template;

use Funnypot\Attack\CannedData;

/**
 * Fills the bounded `{{...}}` directives in a template body/header value. This is the ONLY
 * dynamic step in a funnypot template — a deliberately small, CLOSED vocabulary, never a
 * general expression language, so a template can never execute attacker input. Replacement
 * values are inserted once and never re-scanned (an attacker-reflected `{{...}}` stays inert
 * literal text).
 *
 *   {{canned.passwd|uid|winini}}     shared fake markers (fake /etc/passwd, uid=0(root), win.ini)
 *   {{fake.NAME:hex:N}}              N hex chars, seeded by (persona, NAME) — same NAME ⇒ same value,
 *                                    so one fake secret can appear twice; different NAME ⇒ independent
 *   {{fakeHex:N}}                    positional seeded hex (legacy; prefer named fake.*)
 *   {{match.N}} / {{match.NAME}}     regex capture group (numeric or named) — BOUNDED reflection of the
 *                                    matched attacker bytes (header values are CR/LF-checked by callers)
 *   {{urldecode:match.N}}            percent-decoded capture
 *   {{compute.md5:OPERAND}}          md5/crc32 of an operand (a capture, urldecode:capture, or literal)
 *   {{compute.crc32:OPERAND}}
 *   {{pick:a,b,c}}                   seeded choice from a comma list
 *   {{canary.KEY}}                   operator-supplied tripwire token
 *   {{hex:AABBCC}}                   raw bytes hex2bin(AABBCC) — embed exact bytes (incl. >= 0x80)
 *                                    that the YAML \xNN transport can't carry byte-exact; non-hex
 *                                    chars are stripped, an odd digit count renders '' (never a
 *                                    partial byte). Lets a binary-protocol template be byte-exact.
 *   {{{{ … }}}}                      literal braces (escape) — for pages that must contain real {{ }}
 */
final class DirectiveRenderer
{
    private const CANNED = [
        'passwd' => CannedData::PASSWD,
        'uid' => CannedData::UID,
        'winini' => CannedData::WININI,
        'shadow' => CannedData::SHADOW,
        'group' => CannedData::GROUP,
        'environ' => CannedData::ENVIRON,
    ];

    /** The closed directive prefixes — used by the compile-time lint. */
    public const KNOWN_PREFIXES = ['canned.', 'fake.', 'fakeHex:', 'hex:', 'match.', 'urldecode:match.', 'compute.md5:', 'compute.crc32:', 'pick:', 'canary.'];

    /**
     * @param string             $template body or header value carrying directives
     * @param array<int|string,string> $captures regex capture groups (0 = whole match; names allowed)
     * @param int                $seed     persona seed for deterministic fake values
     * @param array<string,string> $canary  operator tripwire tokens by key
     */
    public function render(string $template, array $captures = [], int $seed = 0, array $canary = []): string
    {
        if (strpos($template, '{{') === false) {
            return $template;
        }

        // Escape: {{{{ }}}} -> literal {{ }} (protect before directive parsing, restore after).
        $template = strtr($template, ['{{{{' => "\x00L\x00", '}}}}' => "\x00R\x00"]);

        $out = (string) preg_replace_callback('/\{\{\s*([^}]+?)\s*\}\}/', function (array $m) use ($captures, $seed, $canary): string {
            return $this->resolve(trim($m[1]), $captures, $seed, $canary);
        }, $template);

        return strtr($out, ["\x00L\x00" => '{{', "\x00R\x00" => '}}']);
    }

    /**
     * @param array<int|string,string> $captures
     * @param array<string,string>     $canary
     */
    private function resolve(string $expr, array $captures, int $seed, array $canary): string
    {
        // Alternatives: first resolvable wins ("{{canary.aws_key | fake.k:hex:20}}").
        foreach (array_map('trim', explode('|', $expr)) as $part) {
            $value = $this->resolveOne($part, $captures, $seed, $canary);
            if ($value !== null && $value !== '') {
                return $value;
            }
        }

        return '';
    }

    /**
     * @param array<int|string,string> $captures
     * @param array<string,string>     $canary
     */
    private function resolveOne(string $part, array $captures, int $seed, array $canary): ?string
    {
        if (strpos($part, 'canned.') === 0) {
            return self::CANNED[substr($part, 7)] ?? null;
        }
        if (strpos($part, 'fake.') === 0) {
            // fake.NAME:ENC:N — ENC in {hex (default), hexupper, b64}. Seed+name derived, so a
            // NAME reused in a template renders the same fabricated value in both places.
            $bits = explode(':', substr($part, 5));
            $name = $bits[0] ?? '';
            $enc = $bits[1] ?? 'hex';
            $len = max(1, (int) ($bits[2] ?? 16));
            $digest = hash('sha256', $seed . '|fake|' . $name);
            if ($enc === 'hexupper') {
                return strtoupper(substr($digest, 0, $len));
            }
            if ($enc === 'b64') {
                return substr(base64_encode((string) hex2bin($digest)), 0, $len);
            }

            return substr($digest, 0, $len);
        }
        if (strpos($part, 'fakeHex:') === 0) {
            $len = max(1, (int) substr($part, 8));

            return substr(hash('sha256', $seed . '|fakehex'), 0, $len);
        }
        if (strpos($part, 'hex:') === 0) {
            // Raw bytes for byte-exact binary frames: hex2bin of the hex digits. Bytes >= 0x80
            // survive here because expansion happens at render time, not in the YAML \xNN transport
            // (which UTF-8-widens high codepoints). Non-hex chars are stripped; an odd digit count
            // yields '' so a malformed directive never emits a partial byte.
            $hex = (string) preg_replace('/[^0-9a-fA-F]/', '', substr($part, 4));

            return strlen($hex) % 2 === 0 ? (string) hex2bin($hex) : '';
        }
        if (strpos($part, 'urldecode:match.') === 0) {
            return rawurldecode($this->capture($captures, substr($part, 16)));
        }
        if (strpos($part, 'match.') === 0) {
            return $this->capture($captures, substr($part, 6));
        }
        if (strpos($part, 'compute.md5:') === 0) {
            return md5($this->operand(substr($part, 12), $captures));
        }
        if (strpos($part, 'compute.crc32:') === 0) {
            return dechex(crc32($this->operand(substr($part, 14), $captures)));
        }
        if (strpos($part, 'pick:') === 0) {
            $opts = array_map('trim', explode(',', substr($part, 5)));

            return $opts === [] ? '' : $opts[crc32($seed . '|pick|' . $part) % count($opts)];
        }
        if (strpos($part, 'canary.') === 0) {
            return $canary[substr($part, 7)] ?? null;
        }

        // Unknown directive -> literal (fail safe; never execute). Compile-time lint catches typos.
        return $part;
    }

    /** @param array<int|string,string> $captures */
    private function capture(array $captures, string $ref): string
    {
        $key = is_numeric($ref) ? (int) $ref : $ref;

        return $captures[$key] ?? '';
    }

    /**
     * Resolve a compute operand: a capture ref, a urldecoded capture, or a literal.
     *
     * @param array<int|string,string> $captures
     */
    private function operand(string $ref, array $captures): string
    {
        if (strpos($ref, 'urldecode:match.') === 0) {
            return rawurldecode($this->capture($captures, substr($ref, 16)));
        }
        if (strpos($ref, 'match.') === 0) {
            return $this->capture($captures, substr($ref, 6));
        }

        return $ref;
    }
}
