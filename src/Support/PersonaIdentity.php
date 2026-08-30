<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

use Funnypot\Core\Support\Fake\FakePeople;

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
        'db.host', 'db.name', 'db.wpName', 'db.user', 'db.password',
        'user.admin.username', 'user.admin.email', 'user.admin.password', 'user.admin.passwordHash',
        'cloud.aws.accessKeyId', 'cloud.aws.secretKey', 'cloud.aws.region',
        'cloud.anthropic.apiKey', 'cloud.openai.apiKey', 'cloud.github.copilotToken',
        'cloud.stripe.secretKey', 'cloud.sendgrid.apiKey', 'cloud.google.apiKey',
        'secret.jwt',
        'php.version',
        'wordpress.version', 'wordpress.theme', 'wordpress.themeVersion',
        // The one canonical WordPress author set for this deploy — five users, index 1 = the admin
        // account (its nicename derives from user.admin.username). Every WP author-enumeration surface
        // (REST /wp/v2/users, author archives, sitemaps, feed bylines) reads THESE, so no two surfaces
        // disagree on who exists. Never carries an email or a login: the REST users endpoint exposes
        // neither to anonymous callers, and neither may leak here.
        'wordpress.user.1.slug', 'wordpress.user.1.name', 'wordpress.user.1.avatar',
        'wordpress.user.2.slug', 'wordpress.user.2.name', 'wordpress.user.2.avatar',
        'wordpress.user.3.slug', 'wordpress.user.3.name', 'wordpress.user.3.avatar',
        'wordpress.user.4.slug', 'wordpress.user.4.name', 'wordpress.user.4.avatar',
        'wordpress.user.5.slug', 'wordpress.user.5.name', 'wordpress.user.5.avatar',
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

    // Engine-neutral / Postgres-plausible host names only. Every config-disclosure page that
    // consumes db.host hardcodes Postgres (pgsql / postgresql / :5432), so a host named for
    // another engine (mysql/mariadb) would contradict the engine claim on the same host.
    private const DB_HOSTS = [
        'localhost', '127.0.0.1', 'db', 'db01', 'db-primary', 'postgres', 'pg01',
        '10.0.0.12', '10.0.1.5', '172.16.0.10',
    ];

    // No 'wp' suffix here: the pgsql app db is never named *_wp. A WordPress install carries its own
    // separate MySQL database (db.wpName = slug_wp), so keeping 'wp' out of this pool guarantees the
    // WP db name and the app db name (db.name) can never collide for any seed.
    private const DB_NAME_SUFFIX = ['prod', 'app', 'main', 'cms', 'db'];

    private const DB_USER_SUFFIX = ['app', 'admin', 'svc', 'user'];

    private const ADMIN_USERNAMES = ['admin', 'administrator', 'root', 'sysadmin', 'webadmin'];

    // Real WordPress theme slugs — bundled defaults plus widely-installed third-party themes — so the
    // active-theme asset path reads like a genuine install. Every slug is [a-z0-9-].
    private const WP_THEMES = [
        'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo', 'twentytwentyone',
        'astra', 'generatepress', 'oceanwp', 'kadence', 'hello-elementor',
    ];

    private const AWS_REGIONS = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-west-2',
        'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'sa-east-1',
    ];

    // Mixed alphabets (upper + lower + digits + a couple of symbols) so fake passwords read like
    // real ones instead of a hex-string generator tell. The db and admin sets differ in symbols and
    // length so the two credentials don't share a recognisable shape. Ambiguous glyphs (0/O, 1/l/I)
    // are dropped so a copied value round-trips. The db symbols are limited to '-' and '_' (both
    // URL-unreserved and YAML-plain-safe): a '#' would parse as a YAML comment when the password is
    // an unquoted scalar, and truncate a DATABASE_URL as an unencoded fragment marker.
    private const DB_PW_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789-_';

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
            // A WordPress install has its own MySQL database, distinct from the pgsql app db (db.name).
            // The suffix pool above excludes 'wp', so this never equals db.name for any seed.
            'db.wpName' => $slug . '_wp',
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
            'cloud.aws.secretKey' => self::awsSecretKey($seed),
            'cloud.aws.region' => self::pick(self::AWS_REGIONS, $seed, 'aws_region'),

            // Synthetic AI-vendor keys. Each shape is exact by design: a secret scanner
            // (trufflehog/gitleaks) only bites when the counts/infix/suffix match the real
            // regex byte-for-byte, so these keep the load-bearing parts of each pattern.
            // Anthropic: 'sk-ant-api03-' + 93 url-safe-base64 chars + the constant 'AA' tail.
            'cloud.anthropic.apiKey' => self::anthropicApiKey($seed),
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
            'cloud.google.apiKey' => self::googleApiKey($seed),
            'secret.jwt' => substr(self::h($seed, 'jwt_secret'), 0, 64),

            // The PHP interpreter version this host claims — the single source of truth for the
            // version shown on any PHP-identity surface (phpinfo, an X-Powered-By the deploy derives
            // from the same persona), so two surfaces never advertise different PHP versions. Derived
            // from the same slug|domain material productVersion() uses, so field() and
            // productVersion('php') always agree.
            'php.version' => self::pickProductVersion($slug, $domain, 'php'),

            // The WordPress core version, active theme and theme version this host claims — the single
            // source of truth for the front-door markers a WP fingerprinter reads (generator meta plus
            // versioned wp-includes/wp-content asset links). Core version is derived like php.version so
            // every tier claiming a WP version for this deploy agrees; theme name/version are seed-picked
            // the same way, keeping the whole WordPress surface coherent per deployment.
            'wordpress.version' => self::pickProductVersion($slug, $domain, 'wordpress'),
            'wordpress.theme' => self::pick(self::WP_THEMES, $seed, 'wp_theme'),
            'wordpress.themeVersion' => self::pickProductVersion($slug, $domain, 'wp-theme'),
        ];

        // The canonical WP author set, flattened onto $fields as wordpress.user.N.{slug,name,avatar}.
        foreach (self::wpUsers($seed, $adminUser) as $i => $u) {
            $n = (string) ($i + 1);
            $fields['wordpress.user.' . $n . '.slug'] = $u['slug'];
            $fields['wordpress.user.' . $n . '.name'] = $u['name'];
            $fields['wordpress.user.' . $n . '.avatar'] = $u['avatar'];
        }

        return new self($fields);
    }

    /**
     * The five deploy-stable WordPress users, keyed 0-4 (id N+1). User 1 IS the admin: its nicename
     * (slug) is derived from user.admin.username so the author set agrees with the admin identity, and
     * WordPress's own default (nicename == login for the first account) is what a real install shows.
     * Display names are seed-derived people (a real site rarely leaves the byline equal to the login).
     * Nicenames are unique per host, as WordPress enforces — a collision gets a numeric suffix.
     *
     * @return array<int,array{slug:string,name:string,avatar:string}>
     */
    private static function wpUsers(int $seed, string $adminUser): array
    {
        $users = [];
        $seen = [];
        for ($i = 1; $i <= 5; $i++) {
            $person = FakePeople::person($seed, 'wp_user_' . $i);
            $slug = $i === 1 ? self::slug($adminUser) : self::slug($person['first'] . '-' . $person['last']);
            $base = $slug;
            $suffix = 2;
            while (isset($seen[$slug])) {
                $slug = $base . '-' . $suffix;
                $suffix++;
            }
            $seen[$slug] = true;
            $users[] = [
                'slug' => $slug,
                'name' => $person['full'],
                'avatar' => self::gravatarHash($seed, 'wp_user_' . $i),
            ];
        }

        return $users;
    }

    /**
     * A gravatar-shaped 32-hex avatar hash, deploy-stable per user. Real WordPress derives it from the
     * MD5 of the user's email; the honeypot exposes no email, so this is a seed-derived stand-in of the
     * same shape. A bare denied digit run cannot occur inside a pure-hex string (no interior word
     * boundary), so no re-roll guard is needed.
     */
    private static function gravatarHash(int $seed, string $field): string
    {
        return md5(self::h($seed, $field . '|avatar'));
    }

    public function field(string $path): ?string
    {
        return $this->fields[$path] ?? null;
    }

    /** Plausible product version banners per key — never a copied real-world signature string. */
    private const PRODUCT_VERSION_POOLS = [
        'mysql' => [
            '10.6.14-MariaDB-log',
            '10.11.6-MariaDB',
            '8.0.35-0ubuntu0.22.04.1',
            '5.7.42-log',
            '10.5.23-MariaDB-1:10.5.23+maria~ubu2004',
        ],
        // Supported PHP patch releases across the 7.4–8.3 range still seen in the wild.
        'php' => [
            '8.3.6',
            '8.2.18',
            '8.1.27',
            '8.0.30',
            '7.4.33',
        ],
        // Plausible recent WordPress core releases — the version advertised on the front-door
        // markers (generator meta + versioned wp-includes asset links). One per deploy.
        'wordpress' => [
            '6.4.3',
            '6.5.5',
            '6.6.2',
            '6.3.4',
            '6.5.2',
        ],
        // The active theme's own version. Deliberately a two-part shape, unlike core's X.Y.Z, so a
        // theme asset's ?ver= can never mechanically match the core assets' ?ver= on the same page.
        'wp-theme' => [
            '1.2',
            '2.4',
            '3.1',
            '1.9',
            '2.0',
            '4.6',
        ],
    ];

    /** Generic semver-shaped fallback for a $product with no dedicated pool above. */
    private const DEFAULT_VERSION_POOL = ['1.0.0', '1.2.3', '2.0.1', '2.4.6', '3.1.4', '4.1.2'];

    /**
     * A stable-per-deployment version string for $product (e.g. "mysql"). Every field on this
     * identity is a pure function of the seed, so hashing off two of them (company.slug/domain are
     * always populated) makes this pure-per-seed too without needing the raw seed itself — any tier
     * that wants to claim a version for the SAME product on the SAME deployment (a skin's banner, a
     * future core-template) calls this and gets the identical string, never a second
     * independently-rolled fake that could disagree. Falls back to a generic semver-shaped pool for
     * an unrecognized product so the method is total.
     */
    public function productVersion(string $product): string
    {
        return self::pickProductVersion(
            $this->fields['company.slug'] ?? '',
            $this->fields['company.domain'] ?? '',
            $product
        );
    }

    /**
     * The version pick behind productVersion(), as a pure static so fromSeed() can seed the
     * php.version field with the exact value productVersion('php') later returns — one derivation,
     * no drift. Keyed off the same slug|domain material, so it stays pure-per-seed.
     */
    private static function pickProductVersion(string $slug, string $domain, string $product): string
    {
        $pool = self::PRODUCT_VERSION_POOLS[$product] ?? self::DEFAULT_VERSION_POOL;
        $seedMaterial = $slug . '|' . $domain;
        $idx = (int) (hexdec(substr(hash('sha256', $seedMaterial . '|product-version|' . $product), 0, 8)) % count($pool));

        return $pool[$idx];
    }

    /**
     * Canonical per-deploy persona-seed derivation, shared by the app (VisualPersona/AppConfig) and the
     * core template tier, so both resolve to the SAME PersonaIdentity for one deployment. $src is the
     * per-deploy material (e.g. FUNNYPOT_PERSONA_SEED/SECRET); callers read their own env and pass it.
     */
    public static function seedFromMaterial(string $src): int
    {
        return (int) hexdec(substr(hash('sha256', 'funnypot-persona|' . $src), 0, 15));
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
     * alphabet (upper + lower + digits + symbols) instead of raw hex. Re-derives with a round tag
     * if the value trips the fingerprint gate's denied digit run (see hitsDeniedDigits).
     */
    private static function password(int $seed, string $field, int $length, string $alphabet): string
    {
        $n = strlen($alphabet);
        for ($round = 0; ; $round++) {
            $h = self::h($seed, $round === 0 ? $field : $field . '|r' . $round);
            $out = '';
            for ($i = 0; $i < $length; $i++) {
                $out .= $alphabet[(int) hexdec(substr($h, $i * 2, 2)) % $n];
            }
            if (!self::hitsDeniedDigits($out)) {
                return $out;
            }
        }
    }

    /**
     * AWS secret key: standard base64 of 30 seed-derived bytes (40 chars, [A-Za-z0-9+/], no
     * padding). Re-rolls on the denied digit run — its '+'/'/' delimiters can bound a bare
     * 6-digit token the fingerprint gate rejects.
     */
    private static function awsSecretKey(int $seed): string
    {
        for ($round = 0; ; $round++) {
            $value = base64_encode((string) hex2bin(substr(
                self::h($seed, $round === 0 ? 'aws_sk' : 'aws_sk|r' . $round), 0, 60
            )));
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /** Anthropic key: 'sk-ant-api03-' + 93 url-safe-base64 chars + the constant 'AA' tail. Re-rolls
     *  on the denied digit run — its '-'/'_' delimiters can bound a bare 6-digit token. */
    private static function anthropicApiKey(int $seed): string
    {
        for ($round = 0; ; $round++) {
            $s = $round === 0 ? '' : '|r' . $round;
            $body = substr(self::base64url((string) hex2bin(
                self::h($seed, 'anthropic_k' . $s) . self::h($seed, 'anthropic_k2' . $s) . self::h($seed, 'anthropic_k3' . $s)
            )), 0, 93);
            $value = 'sk-ant-api03-' . $body . 'AA';
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /** Google API key: 'AIza' + 35 url-safe-base64 chars. Re-rolls on the denied digit run — its
     *  '-'/'_' delimiters can bound a bare 6-digit token. */
    private static function googleApiKey(int $seed): string
    {
        for ($round = 0; ; $round++) {
            $value = 'AIza' . substr(self::base64url((string) hex2bin(
                self::h($seed, $round === 0 ? 'google_k' : 'google_k|r' . $round)
            )), 0, 35);
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /**
     * True if a rendered secret carries the fingerprint gate's denied bare-6-digit token
     * (\b9\d{5}\b). A served body that trips it is classified as canned, so the boundary-prone
     * generators re-derive until clean — terminating in one or two rounds almost surely.
     */
    private static function hitsDeniedDigits(string $value): bool
    {
        return preg_match('/\b9\d{5}\b/', $value) === 1;
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
