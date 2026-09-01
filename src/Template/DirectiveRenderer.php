<?php

declare(strict_types=1);

namespace Funnypot\Core\Template;

use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\Support\Fake\FakePeople;
use Funnypot\Core\Support\PersonaIdentity;

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
 *   {{fake.person.full:KEY}}         one coherent fake person via Support\Fake\FakePeople, keyed by
 *   {{fake.person.username:KEY}}     (seed, KEY) — the SAME KEY across these directives in one row
 *   {{fake.person.email:KEY}}        yields a full/username/email that all agree; email domain is the
 *                                    seed's persona company.domain (falls back to 'internal'). KEY is
 *                                    an arbitrary token; the sub-field {full,username,email} is a
 *                                    CLOSED set (unlike fake.NAME) — an unknown one fails the lint.
 *   {{fakeHex:N}}                    positional seeded hex (legacy; prefer named fake.*)
 *   {{match.N}} / {{match.NAME}}     regex capture group (numeric or named) — BOUNDED reflection of the
 *                                    matched attacker bytes (header values are CR/LF-checked by callers)
 *   {{urldecode:match.N}}            percent-decoded capture
 *   {{compute.md5:OPERAND}}          md5/crc32 of an operand (a capture, urldecode:capture, or literal)
 *   {{compute.crc32:OPERAND}}
 *   {{pick:a,b,c}}                   seeded choice from a comma list
 *   {{canary.KEY}}                   operator-supplied tripwire token
 *   {{persona.PATH}}                 one coherent fake identity for the seed (company, db, admin,
 *                                    cloud) — PATH is a CLOSED field set (Support\PersonaIdentity);
 *                                    an unknown subfield renders '' (never the literal)
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
        'hostname' => CannedData::HOSTNAME,
        'ssh_private_key' => CannedData::SSH_PRIVATE_KEY,
        'environ' => CannedData::ENVIRON,
        'k8s_sa_unsigned' => CannedData::K8S_SA_UNSIGNED,
    ];

    /** The closed directive prefixes — used by the compile-time lint. */
    public const KNOWN_PREFIXES = ['canned.', 'fake.', 'volatile.', 'fakeHex:', 'hex:', 'match.', 'urldecode:match.', 'xml:match.', 'compute.md5:', 'compute.crc32:', 'pick:', 'canary.', 'persona.'];

    /** The closed set of valid fake.person.* sub-fields — used by the compile-time lint (mirrors
     *  PersonaIdentity::FIELDS' role for persona.*; unlike a plain fake.NAME, this sub-field is
     *  fixed, so a typo here would otherwise render '' at runtime and silently drop the marker). */
    public const PERSON_FIELDS = ['full', 'username', 'email'];

    /**
     * One PersonaIdentity per seed. A renderer instance is long-lived and reused across many
     * requests, so the memo is keyed by seed (not a single cached identity) — different seeds in
     * flight must each resolve their own coherent identity.
     *
     * @var array<int,PersonaIdentity>
     */
    private $personaMemo = [];

    /**
     * Per-deploy identity seed. When set, ALL {{persona.*}} fields and the fake.person.email domain
     * resolve from THIS seed instead of the per-request render seed, so the template tier and the app
     * LLM tier present ONE coherent site identity. null (default) keeps identity on the render seed
     * (per-request, today's behaviour) — a fail-safe, so an un-wired construction site degrades rather
     * than crashes. Fabricated secrets ({{fake.*}}) always use the render seed and stay per-request.
     *
     * @var int|null
     */
    private $personaSeed;

    /**
     * Master arm for the {{volatile.*}} proof-token directive (FP-0232). false (default) ⇒ a
     * {{volatile.NAME:ENC:N}} directive delegates to the stable seeded {{fake.NAME:ENC:N}} path, so a
     * default build is byte-identical to today and every compile-time render check stays deterministic.
     * true ⇒ the directive mints a fresh, non-reproducible token from CSPRNG entropy (random_bytes) on
     * every render, so an identical probe never reproduces the same proof (the confirmation-resistant
     * tarpit). Off by default and fail-safe — an un-wired construction site degrades to the stable path.
     * Persona identity ({{persona.*}}) and every other {{fake.*}} cell are untouched by this arm.
     *
     * @var bool
     */
    private $volatileProof;

    public function __construct(?int $personaSeed = null, bool $volatileProof = false)
    {
        $this->personaSeed = $personaSeed;
        $this->volatileProof = $volatileProof;
    }

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
        if (strpos($part, 'fake.person.') === 0) {
            // fake.person.{full,username,email}:KEY — a coherent fake person from the shared
            // FakePeople generator. The SAME KEY reused across these three directives in one row
            // draws the SAME person (FakePeople::person is a pure function of (seed, KEY)), so
            // full/username/email always agree — mirroring the app tier's row-coherence pattern.
            $bits = explode(':', substr($part, 12), 2);
            $field = $bits[0];
            $key = $bits[1] ?? '';
            if (!in_array($field, self::PERSON_FIELDS, true)) {
                return null; // unknown sub-field -> fail safe; compile-time lint catches the typo
            }
            $person = FakePeople::person($seed, $key);
            if ($field === 'full') {
                return $person['full'];
            }
            if ($field === 'username') {
                return $person['userName'];
            }
            // email: local-part from the person, domain from the seed's coherent persona identity
            // so the address matches the same company any persona.* directives show on the page.
            $domain = $this->personaField($seed, 'company.domain');

            return FakePeople::email($person, $domain !== '' ? $domain : 'internal');
        }
        if (strpos($part, 'volatile.') === 0) {
            // volatile.NAME:ENC:N — a proof-token carrier sharing the fake.NAME:ENC:N grammar (FP-0232).
            // OFF (the default arm): delegate to the stable seeded fake.NAME path so a default build is
            // LITERALLY the fake.NAME bytes (one source of truth) — byte-identical to today, and the
            // compile-time render checks (assertMarkers, run with the arm off at seed 0) stay
            // deterministic. ON: draw the SAME encoding from fresh CSPRNG entropy so the token is
            // non-reproducible per request — the confirmation-resistant tarpit — O(1), no state.
            $spec = substr($part, 9); // "NAME:ENC:N"
            if (!$this->volatileProof) {
                return $this->resolveOne('fake.' . $spec, $captures, $seed, $canary);
            }

            return $this->volatileToken($spec);
        }
        if (strpos($part, 'fake.') === 0) {
            // fake.NAME:ENC:N — ENC in {hex (default), hexupper, b64, b64url, dec}. Seed+name derived,
            // so a NAME reused in a template renders the same fabricated value in both places.
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
            if ($enc === 'b64url') {
                // URL-safe base64, unpadded — the alphabet a JWT/JWK segment must use ([A-Za-z0-9_-],
                // no '+', '/', '='). One 32-byte digest gives 43 chars; for a length beyond that
                // (e.g. :342 for a plausible RSA-2048 modulus `n`) chain raw sha256 to extend the byte
                // material — exactly like the `dec` encoder below — so the cap is no longer a no-op.
                // For any len <= 43 the loop never runs, so existing values stay byte-identical.
                $material = (string) hex2bin($digest);
                while (strlen(rtrim(strtr(base64_encode($material), '+/', '-_'), '=')) < $len) {
                    $material .= hash('sha256', $material, true);
                }

                return substr(rtrim(strtr(base64_encode($material), '+/', '-_'), '='), 0, $len);
            }
            if ($enc === 'dec') {
                // All-digit field (e.g. a Firebase sender id / GCP project number). Draw each digit
                // uniformly by rejection-sampling digest bytes: a byte >= 250 is discarded so the
                // accepted range 0..249 is an exact multiple of 10 and byte % 10 carries no low-digit
                // skew. The first digit also rejects 0 — a real project/sender number never has a
                // leading zero. Deterministic per (seed, name); re-hash (raw) to extend past 32 bytes.
                $digits = '';
                $material = (string) hex2bin($digest);
                $pos = 0;
                while (strlen($digits) < $len) {
                    if ($pos >= strlen($material)) {
                        $material = hash('sha256', $material, true);
                        $pos = 0;
                    }
                    $byte = ord($material[$pos]);
                    $pos++;
                    if ($byte >= 250) {
                        continue;
                    }
                    $digit = $byte % 10;
                    if ($digits === '' && $digit === 0) {
                        continue;
                    }
                    $digits .= (string) $digit;
                }

                return $digits;
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
        if (strpos($part, 'xml:match.') === 0) {
            // XML-escape a reflected capture before it lands in an XML body — a render-layer backstop
            // so a widened capture class can never inject markup into the fault XML.
            return htmlspecialchars($this->capture($captures, substr($part, 10)), ENT_QUOTES | ENT_XML1, 'UTF-8');
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
        if (strpos($part, 'persona.') === 0) {
            return $this->personaField($seed, substr($part, 8));
        }

        // Unknown directive -> literal (fail safe; never execute). Compile-time lint catches typos.
        return $part;
    }

    /**
     * The ARMED volatile-proof path (FP-0232): parse the fake.NAME:ENC:N grammar identically, but draw
     * the material from a fresh CSPRNG read (random_bytes) instead of the seeded sha256 digest, so the
     * token is non-reproducible per render — a Tier-H retester can never re-quote it. NAME is ignored on
     * this path (entropy is name-independent); it is kept in the grammar only so one authored directive
     * serves both the ON and OFF (seeded fake) paths. O(1), no state. Supported encodings are the
     * proof-shaped hex / hexupper / b64 / b64url — all inherently CR/LF/NUL-free; length is capped
     * exactly as fake.NAME caps it. The all-digit `dec` encoding matches the fake.NAME `dec` character
     * class (armed == off shape): digits only, leading digit non-zero, width N — drawn from fresh CSPRNG
     * bytes here instead of the seeded digest so the token is non-reproducible while staying all-digits.
     */
    private function volatileToken(string $spec): string
    {
        $bits = explode(':', $spec);
        $enc = $bits[1] ?? 'hex';
        $len = max(1, (int) ($bits[2] ?? 16));
        // 32 fresh bytes → a 64-hex-char digest, the SAME width as the seeded fake digest, so the
        // length caps below behave identically to fake.NAME.
        $raw = random_bytes(32);
        $digest = bin2hex($raw);
        if ($enc === 'hexupper') {
            return strtoupper(substr($digest, 0, $len));
        }
        if ($enc === 'b64') {
            return substr(base64_encode($raw), 0, $len);
        }
        if ($enc === 'b64url') {
            // URL-safe base64, unpadded — same alphabet as fake.NAME's b64url ([A-Za-z0-9_-]).
            return substr(rtrim(strtr(base64_encode($raw), '+/', '-_'), '='), 0, $len);
        }
        if ($enc === 'dec') {
            // All-digit field, EXACTLY the fake.NAME `dec` shape (so armed and off share a character
            // class, not just differ in bytes): rejection-sample fresh CSPRNG bytes — a byte >= 250 is
            // discarded so the accepted range 0..249 is an exact multiple of 10 and byte % 10 carries no
            // low-digit skew; the leading digit rejects 0. Uniform enough for a decoy token, not crypto.
            // Entropy is drawn fresh each render (a new random_bytes read to extend past 32 bytes), so
            // the token is non-reproducible — the confirmation-resistant tarpit — while staying digits.
            $digits = '';
            $material = $raw;
            $pos = 0;
            while (strlen($digits) < $len) {
                if ($pos >= strlen($material)) {
                    $material = random_bytes(32);
                    $pos = 0;
                }
                $byte = ord($material[$pos]);
                $pos++;
                if ($byte >= 250) {
                    continue;
                }
                $digit = $byte % 10;
                if ($digits === '' && $digit === 0) {
                    continue;
                }
                $digits .= (string) $digit;
            }

            return $digits;
        }

        return substr($digest, 0, $len);
    }

    /**
     * Resolve one field of the seed's coherent persona identity. An unknown subfield renders ''
     * (fail-safe) so a typo never leaks the literal directive; the compile-time lint rejects it.
     */
    private function personaField(int $seed, string $path): string
    {
        // Identity is per-deploy when a persona seed was injected, else per-request (the render seed).
        $identSeed = $this->personaSeed ?? $seed;
        if (!isset($this->personaMemo[$identSeed])) {
            $this->personaMemo[$identSeed] = PersonaIdentity::fromSeed($identSeed);
        }

        return $this->personaMemo[$identSeed]->field($path) ?? '';
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
