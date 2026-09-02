<?php

declare(strict_types=1);

namespace Funnypot\Core\Template;

use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\Response\InjectionPayloads;
use Funnypot\Core\Support\Fake\FakePeople;
use Funnypot\Core\Support\Fake\FakeSecrets;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SeededIndex;
use Funnypot\Core\Support\SubSeed;

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
 *   {{xml:match.N}}                  XML-escaped capture (ENT_XML1) — render-layer backstop for XML bodies
 *   {{html:match.N}}                 HTML-escaped capture (ENT_HTML5) — render-layer backstop for HTML bodies;
 *                                    both only ever NARROW reflected bytes, never a new sink
 *   {{compute.md5:OPERAND}}          md5/crc32 of an operand (a capture, urldecode:capture, or literal)
 *   {{compute.crc32:OPERAND}}
 *   {{pick:a,b,c}}                   seeded choice from a comma list (keyed on the whole list, so two
 *                                    picks over an identical list always agree)
 *   {{pick:KEY:a,b,c}}               seeded choice keyed on KEY instead of the list — two picks with the
 *                                    same KEY agree, different KEYs over one list de-correlate. KEY is the
 *                                    text up to the first ':' that precedes the first ','; a list whose
 *                                    first element carries no such ':' parses exactly as the un-keyed form
 *                                    (byte-identical for every existing template).
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
    public const KNOWN_PREFIXES = ['canned.', 'fake.', 'volatile.', 'misdirect', 'fakeHex:', 'hex:', 'match.', 'urldecode:match.', 'xml:match.', 'html:match.', 'compute.md5:', 'compute.crc32:', 'pick:', 'canary.', 'persona.'];

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

    /**
     * Master arm for the {{misdirect}} chat-floor misdirection directive (FP-0238) — the exact shape of
     * $volatileProof. false (default) ⇒ {{misdirect}} resolves to '' so the authored alternative (the
     * benign nonsense pick) wins and every served body is byte-identical to today; a package-embedded
     * host that has not opted in never emits attacker-facing deception. true ⇒ {{misdirect}} resolves to
     * a seeded pick from InjectionPayloads::CHAT_MISDIRECTION (built from constants + seed only, never
     * from a capture, so it is non-reflecting). Reuses Config::$promptInjectionSeeding — the same opt-in
     * the route-decoy injection rides — so there is no new gate. Off by default and fail-safe.
     *
     * @var bool
     */
    private $promptInjectionSeeding;

    public function __construct(?int $personaSeed = null, bool $volatileProof = false, bool $promptInjectionSeeding = false)
    {
        $this->personaSeed = $personaSeed;
        $this->volatileProof = $volatileProof;
        $this->promptInjectionSeeding = $promptInjectionSeeding;
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
        if (strpos($part, 'misdirect') === 0) {
            // {{misdirect}} — the gated chat-floor misdirection directive (FP-0238), same OFF/ON shape as
            // {{volatile.*}}. OFF (the default arm): resolve to '' so the authored alternative — the
            // benign nonsense {{pick:...}} — wins, and the served body is byte-identical to today (the
            // fail-safe for package-embedded hosts). ON: a seeded pick from CHAT_MISDIRECTION, built from
            // the constant corpus + seed ONLY (never a capture), so it is non-reflecting. The corpus is
            // inert English with no `"`/`\`/`{{`, so the pick lands byte-safe inside the JSON content
            // string it fills; a returned value is inserted once and never re-scanned (its single `{` in
            // FLAG{...} stays literal). Returns '' when the arm is off OR the corpus is empty so resolve()
            // falls through to the next alternative in both cases.
            if (!$this->promptInjectionSeeding) {
                return '';
            }
            $corpus = InjectionPayloads::CHAT_MISDIRECTION;

            return $corpus === [] ? '' : $corpus[SeededIndex::pick($seed . '|misdirect', count($corpus))];
        }
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
        if (strpos($part, 'fake.flag:') === 0) {
            // fake.flag:KEY — an inert CTF-sentinel honeytoken `FLAG.{<40-hex>}.GALF` (one source of
            // truth: FakeSecrets::flag). Placed BEFORE the generic fake. branch so the `flag` NAME is
            // routed here, not treated as a fake.NAME:ENC:N (which would render a bare hex run without
            // the fingerprint-safe wrapper). KEY reused across a template renders the same token twice.
            return FakeSecrets::flag($seed, substr($part, 10));
        }
        if (strpos($part, 'fake.') === 0) {
            // fake.NAME:ENC:N — ENC in {hex (default), hexupper, b64, b64url, dec}. Seed+name derived,
            // so a NAME reused in a template renders the same fabricated value in both places.
            $bits = explode(':', substr($part, 5));
            $name = $bits[0] ?? '';
            $enc = $bits[1] ?? 'hex';
            $len = max(1, (int) ($bits[2] ?? 16));
            // {{fake.*}} is keyed on the per-request RENDER seed by design (per-attacker), so $seed is
            // the input here — not the deploy identity seed. Byte-identical to the historical
            // `hash('sha256', $seed . '|fake|' . $name)`.
            $digest = SubSeed::digest($seed, SubSeed::NS_FAKE, $name);
            if ($enc === 'hexupper') {
                return strtoupper(substr($digest, 0, $len));
            }
            if ($enc === 'b64') {
                // Standard base64. One 32-byte digest encodes to 44 chars — the 44th being a single
                // '=' pad — so any len <= 44 is served straight from that padded encode, byte-identical
                // to before (this preserves the luckily-correct Laravel APP_KEY `b64:44` shape, which
                // legitimately ends '='). For a LONGER request a single digest can't reach it, and
                // simply extending the padded encode would leave a '=' stranded MID-STREAM every ~44
                // chars — structurally impossible base64, a one-glance honeypot tell (this is what the
                // 22 PEM body lines and the IMDS token hit today). So chain raw sha256 to extend the
                // material — like the b64url/dec encoders — and serve from the '='-STRIPPED stream, a
                // clean [A-Za-z0-9+/] run of exactly the requested width.
                if ($len <= 44) {
                    return substr(base64_encode((string) hex2bin($digest)), 0, $len);
                }
                $material = (string) hex2bin($digest);
                while (strlen(rtrim(base64_encode($material), '=')) < $len) {
                    $material .= hash('sha256', $material, true);
                }

                return substr(rtrim(base64_encode($material), '='), 0, $len);
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
        if (strpos($part, 'html:match.') === 0) {
            // HTML-escape a reflected capture before it lands in a text/html body — the render-layer
            // backstop for HTML the way xml:match. is for XML (HTML5 entity semantics; escapes
            // <>&"'). A pure narrowing of what reflected bytes can do, never a new reflection sink.
            return htmlspecialchars($this->capture($captures, substr($part, 11)), ENT_QUOTES | ENT_HTML5, 'UTF-8');
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
            // {{pick:a,b,c}} — seeded choice, keyed by default on the WHOLE directive text (so two
            // picks over an identical list always agree). Optional {{pick:KEY:a,b,c}}: if a ':' occurs
            // BEFORE the first ',', the text up to it is KEY and the seed material keys on KEY instead,
            // so two picks with the same KEY agree while different KEYs over one list de-correlate. A
            // list whose first element carries no early ':' keeps today's material EXACTLY (the pick
            // stays byte-identical for every shipped template — none carries a ':' before its comma).
            $rest = substr($part, 5);
            $colon = strpos($rest, ':');
            $comma = strpos($rest, ',');
            if ($colon !== false && ($comma === false || $colon < $comma)) {
                $key = substr($rest, 0, $colon);
                $opts = array_map('trim', explode(',', substr($rest, $colon + 1)));
                $material = $seed . '|pick|' . $key;
            } else {
                $opts = array_map('trim', explode(',', $rest));
                $material = $seed . '|pick|' . $part;
            }

            return $opts === [] ? '' : $opts[SeededIndex::pick($material, count($opts))];
        }
        if (strpos($part, 'canary.') === 0) {
            return $canary[substr($part, 7)] ?? null;
        }
        if (strpos($part, 'persona.') === 0) {
            return $this->personaField($seed, substr($part, 8));
        }

        // Unknown directive -> '' (via null so resolve()'s '|'-alternatives still cascade), aligning
        // with every other fail-safe here (an unknown persona subfield / fake.person field already
        // renders ''). Serving the literal directive text would be both a honeypot tell and the lone
        // fail-open path. The compile-time assertKnownDirectives lint guarantees no shipped or compiled
        // template reaches this — it only fires for a hand-crafted/out-of-band artifact, where '' is
        // the safer failure.
        return null;
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
            // Mirror the fake.NAME b64 cap exactly (the documented "capped exactly as fake.NAME"
            // contract): len <= 44 straight from the 44-char padded encode, a longer request chains
            // fresh CSPRNG reads and serves from the '='-STRIPPED stream so no '=' is ever stranded
            // mid-stream (an impossible-base64 tell). Entropy is fresh each read — non-reproducible.
            if ($len <= 44) {
                return substr(base64_encode($raw), 0, $len);
            }
            $material = $raw;
            while (strlen(rtrim(base64_encode($material), '=')) < $len) {
                $material .= random_bytes(32);
            }

            return substr(rtrim(base64_encode($material), '='), 0, $len);
        }
        if ($enc === 'b64url') {
            // URL-safe base64, unpadded — same alphabet as fake.NAME's b64url ([A-Za-z0-9_-]). A single
            // 32-byte read gives 43 chars; a longer request chains fresh CSPRNG reads to honor N, so the
            // cap matches fake.NAME's b64url instead of silently truncating at 43.
            $material = $raw;
            while (strlen(rtrim(strtr(base64_encode($material), '+/', '-_'), '=')) < $len) {
                $material .= random_bytes(32);
            }

            return substr(rtrim(strtr(base64_encode($material), '+/', '-_'), '='), 0, $len);
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
        $identSeed = $this->identitySeed($seed);
        if (!isset($this->personaMemo[$identSeed])) {
            $this->personaMemo[$identSeed] = PersonaIdentity::fromSeed($identSeed);
        }

        return $this->personaMemo[$identSeed]->field($path) ?? '';
    }

    /**
     * The one fail-toward-stable-fallback rule for persona identity (FP-0276): the injected per-deploy
     * persona seed when set, else the per-request render seed (still deterministic per request, never a
     * crash or a per-request random). Named once here so no site — this class's or a sibling's — writes
     * `?? $seed` a second time.
     */
    private function identitySeed(int $renderSeed): int
    {
        return $this->personaSeed ?? $renderSeed;
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
