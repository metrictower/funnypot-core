<?php

declare(strict_types=1);

namespace Funnypot\Support;

/**
 * A single coherent fake identity for one persona seed — the company, its database, an
 * admin account, and cloud credentials that all agree with each other. Dependent fields are
 * string-composed from their parents (email uses the admin username AND the company domain;
 * db.name/db.user carry the company slug) so a synthesized response never contradicts itself
 * across two different fakes.
 *
 * Every value is a pure function of the seed plus the frozen dictionaries below, so the same
 * seed always yields byte-identical fields (a re-scan by the same attacker sees one stable
 * host). Sub-hashes are tagged `|persona|` — distinct from DirectiveRenderer's `fake.NAME`
 * tag `|fake|` — so a persona value can never collide with a `{{fake.NAME}}` value.
 */
final class PersonaIdentity
{
    /** The closed set of valid dotted field paths — used by the compile-time directive lint. */
    public const FIELDS = [
        'company.name', 'company.slug', 'company.tld', 'company.domain',
        'db.host', 'db.name', 'db.user', 'db.password',
        'user.admin.username', 'user.admin.email', 'user.admin.password', 'user.admin.passwordHash',
        'cloud.aws.accessKeyId', 'cloud.aws.secretKey', 'cloud.aws.region',
        'cloud.anthropic.apiKey', 'cloud.openai.apiKey', 'cloud.github.copilotToken',
        'cloud.stripe.secretKey', 'cloud.sendgrid.apiKey', 'cloud.google.apiKey',
        'secret.jwt',
    ];

    /**
     * Single-token company base names, so a slug is a clean lowercase word (no hyphens). These are
     * coined blends, not famous-fiction placeholders (Acme/Contoso/Umbrella/…) — those read as a
     * demo to any experienced attacker, and some resolve to real third-party domains. Kept single
     * token because the coherence invariant (domain = slug.tld, db = slug_) depends on a clean slug.
     */
    private const COMPANIES = [
        'Velthora', 'Cendriq', 'Bravonic', 'Quorlane', 'Halvex', 'Trivello', 'Ostramer', 'Calyndor',
        'Marnovis', 'Sylvantic', 'Drovance', 'Kelmora', 'Pravelli', 'Zundara', 'Corvyne', 'Elmarque',
        'Torvexa', 'Andelio', 'Bracovia', 'Fennovis', 'Wexlaris', 'Grovanti', 'Lumbriq', 'Vantessa',
        'Norweld', 'Palvora', 'Cindovia', 'Merrivox', 'Ravendil', 'Solvanic', 'Truvello', 'Yandric',
        'Astrivo', 'Bexworth', 'Cravonto', 'Delmarque', 'Ferngate', 'Voltraq', 'Kyventa', 'Nimvello',
    ];

    private const TLDS = ['com', 'net', 'io', 'co', 'cloud', 'dev', 'app', 'org', 'tech'];

    private const DB_HOSTS = [
        'localhost', '127.0.0.1', 'db', 'db01', 'db-primary', 'mysql', 'mariadb',
        '10.0.0.12', '10.0.1.5', '172.16.0.10',
    ];

    private const DB_NAME_SUFFIX = ['prod', 'app', 'main', 'cms', 'db', 'wp'];

    private const DB_USER_SUFFIX = ['app', 'admin', 'svc', 'user'];

    private const ADMIN_USERNAMES = ['admin', 'administrator', 'root', 'sysadmin', 'webadmin'];

    private const AWS_REGIONS = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-west-2',
        'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'sa-east-1',
    ];

    // Mixed alphabets (upper + lower + digits + a couple of symbols) so fake passwords read like
    // real ones instead of a hex-string generator tell. The db and admin sets differ in symbols and
    // length so the two credentials don't share a recognisable shape. Ambiguous glyphs (0/O, 1/l/I)
    // are dropped so a copied value round-trips.
    private const DB_PW_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789-_#';

    private const ADMIN_PW_ALPHABET = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!*.';

    /**
     * Flat map keyed by dotted path. Private on purpose: DirectiveRenderer memoises one instance per
     * seed for process life, so an external write would poison every later render. Read via field().
     *
     * @var array<string,string>
     */
    private $fields;

    /** @param array<string,string> $fields */
    private function __construct(array $fields)
    {
        $this->fields = $fields;
    }

    public static function fromSeed(int $seed): self
    {
        $company = self::pick(self::COMPANIES, $seed, 'company');
        $slug = self::slug($company);
        $tld = self::pick(self::TLDS, $seed, 'tld');
        $domain = $slug . '.' . $tld;

        $adminUser = self::pick(self::ADMIN_USERNAMES, $seed, 'admin_user');

        $fields = [
            'company.name' => $company,
            'company.slug' => $slug,
            'company.tld' => $tld,
            'company.domain' => $domain,

            'db.host' => self::pick(self::DB_HOSTS, $seed, 'db_host'),
            'db.name' => $slug . '_' . self::pick(self::DB_NAME_SUFFIX, $seed, 'db_name'),
            'db.user' => $slug . '_' . self::pick(self::DB_USER_SUFFIX, $seed, 'db_user'),
            'db.password' => self::password($seed, 'db_pw', 20, self::DB_PW_ALPHABET),

            'user.admin.username' => $adminUser,
            'user.admin.email' => $adminUser . '@' . $domain,
            'user.admin.password' => self::password($seed, 'admin_pw', 16, self::ADMIN_PW_ALPHABET),
            'user.admin.passwordHash' => self::bcryptHash($seed),

            'cloud.aws.accessKeyId' => self::awsAccessKeyId($seed),
            // Standard base64 of 30 seed-derived bytes: exactly 40 chars, [A-Za-z0-9+/], no padding.
            // A real AWS secret key uses the standard alphabet, so the fake must too or a secret
            // scanner's regex rejects it and it never baits.
            'cloud.aws.secretKey' => base64_encode((string) hex2bin(substr(self::h($seed, 'aws_sk'), 0, 60))),
            'cloud.aws.region' => self::pick(self::AWS_REGIONS, $seed, 'aws_region'),

            // Synthetic AI-vendor keys. Each shape is exact by design: a secret scanner
            // (trufflehog/gitleaks) only bites when the counts/infix/suffix match the real
            // regex byte-for-byte, so these keep the load-bearing parts of each pattern.
            // Anthropic: 'sk-ant-api03-' + 93 url-safe-base64 chars + the constant 'AA' tail.
            'cloud.anthropic.apiKey' => 'sk-ant-api03-' . substr(self::base64url((string) hex2bin(
                self::h($seed, 'anthropic_k') . self::h($seed, 'anthropic_k2') . self::h($seed, 'anthropic_k3')
            )), 0, 93) . 'AA',
            // OpenAI: 'sk-' + 20 + the constant 'T3BlbkFJ' infix + 20.
            'cloud.openai.apiKey' => 'sk-' . self::base62($seed, 'openai_k', 20) . 'T3BlbkFJ' . self::base62($seed, 'openai_k2', 20),
            // GitHub Copilot user-to-server token: 'ghu_' + 36.
            'cloud.github.copilotToken' => 'ghu_' . self::base62($seed, 'copilot_k', 36),

            // Config-file-disclosure secrets — the credentials a leaked config file carries. Each
            // shape is exact so a secret scanner over the loot bites: Stripe live secret key
            // ('sk_live_' + 24 base62), SendGrid key ('SG.' + 22 + '.' + 43), Google API key
            // ('AIza' + 35 url-safe-base64), and a 64-hex JWT signing secret. Rendered per attacker
            // and coherent across every file the same host discloses them in.
            'cloud.stripe.secretKey' => 'sk_live_' . self::base62($seed, 'stripe_sk', 24),
            'cloud.sendgrid.apiKey' => 'SG.' . self::base62($seed, 'sg1', 22) . '.' . self::base62($seed, 'sg2', 43),
            'cloud.google.apiKey' => 'AIza' . substr(self::base64url((string) hex2bin(self::h($seed, 'google_k'))), 0, 35),
            'secret.jwt' => substr(self::h($seed, 'jwt_secret'), 0, 64),
        ];

        return new self($fields);
    }

    public function field(string $path): ?string
    {
        return $this->fields[$path] ?? null;
    }

    /**
     * Per-field sub-hash. The `|persona|` tag is REQUIRED: it separates this space from
     * DirectiveRenderer's `fake.NAME` space (`|fake|`), so the two never collide on one seed.
     */
    private static function h(int $seed, string $field): string
    {
        return hash('sha256', $seed . '|persona|' . $field);
    }

    /**
     * Deterministic dictionary pick for a field.
     *
     * @param array<int,string> $dict
     */
    private static function pick(array $dict, int $seed, string $field): string
    {
        $idx = (int) (hexdec(substr(self::h($seed, $field), 0, 8)) % count($dict));

        return $dict[$idx];
    }

    /**
     * A valid 60-char bcrypt shape: the `$2y$10$` cost header plus 53 chars in bcrypt's
     * `./A-Za-z0-9` alphabet. 40 seed-derived bytes give a base64 run long enough to fill
     * the 53-char tail without ever hitting `=` padding.
     *
     * The 22-char salt encodes a 128-bit value into 132 base64 bits, so its final char carries only
     * 2 meaningful bits and its low 4 bits are always zero in a real bcrypt salt — meaning only `.`,
     * `O`, `e`, `u` (alphabet indices 0/16/32/48) can appear there. A raw base64 char lands outside
     * that set ~93% of the time, an impossible-salt tell, so we force it to a legal padding char.
     */
    private static function bcryptHash(int $seed): string
    {
        $bytes = (string) hex2bin(self::h($seed, 'admin_ph') . substr(self::h($seed, 'admin_ph2'), 0, 16));
        $blob = substr(strtr(base64_encode($bytes), '+/', './'), 0, 53);

        $pad = ['.', 'O', 'e', 'u'];
        $blob[21] = $pad[$seed & 3]; // last salt char (index 21 of the 53-char tail)

        return '$2y$10$' . $blob;
    }

    /**
     * A deterministic, human-plausible password: seed-derived digest bytes mapped into a mixed
     * alphabet (upper + lower + digits + symbols) instead of raw hex.
     */
    private static function password(int $seed, string $field, int $length, string $alphabet): string
    {
        $h = self::h($seed, $field);
        $n = strlen($alphabet);
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= $alphabet[(int) hexdec(substr($h, $i * 2, 2)) % $n];
        }

        return $out;
    }

    /** 'AKIA' + 16 chars from the base32 alphabet [A-Z2-7], matching a real access-key-id shape. */
    private static function awsAccessKeyId(int $seed): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $h = self::h($seed, 'aws_ak');
        $body = '';
        for ($i = 0; $i < 16; $i++) {
            $body .= $alphabet[(int) hexdec(substr($h, $i * 2, 2)) % 32];
        }

        return 'AKIA' . $body;
    }

    /**
     * `$len` chars from the 62-char [A-Za-z0-9] alphabet, seed-derived. Same per-char loop as
     * awsAccessKeyId but base62; it draws further sub-hashes when one digest's 32 bytes can't
     * cover the length (a 36-char token needs 72 hex, past a single 64-hex-char hash).
     */
    private static function base62(int $seed, string $field, int $len): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $hex = self::h($seed, $field);
        $round = 1;
        while (strlen($hex) < $len * 2) {
            $hex .= self::h($seed, $field . $round);
            $round++;
        }
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= $alphabet[(int) hexdec(substr($hex, $i * 2, 2)) % 62];
        }

        return $out;
    }

    /** URL-safe unpadded base64 ([A-Za-z0-9_-]) — the alphabet an API-key body carries. */
    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** Replicated from Compiler\ProductIdentity::slug — kept local so Support never depends on Compiler. */
    private static function slug(string $s): string
    {
        $s = strtolower(trim($s));
        $s = preg_replace('/[^a-z0-9]+/', '-', $s) ?? '';

        return trim($s, '-');
    }
}
