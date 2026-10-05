<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

use Funnypot\Core\Support\Fake\FakePeople;

/**
 * A single coherent fake identity for one persona seed — the company, its database, an
 * admin account, and cloud credentials that all agree with each other. Dependent fields are
 * string-composed from their parents (email uses the admin username AND the company domain;
 * db.name/db.user carry the company slug) so a synthesized response never contradicts itself
 * across two different fakes. The cloud story is coherent the same way: the AWS region is drawn
 * once and its ElastiCache short code (cloud.aws.regionCode) is a lookup off that one draw, so every
 * config-disclosure surface (.env, wp-config, .aws/config, terraform.tfstate) discloses ONE region.
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
        // The ElastiCache/short region code (`use1`, `euw1`, `apse2`, …) that AWS embeds inside
        // `*.cache.amazonaws.com` endpoints. A pure table lookup off cloud.aws.region (the codes are
        // AWS's actual endpoint tokens — `ap-southeast-1` is `apse1`, not `apso1` — so a lookup, never
        // a mechanical derivation), so the deploy draws its region ONCE and every host segment follows it.
        'cloud.aws.regionCode',
        'cloud.anthropic.apiKey', 'cloud.openai.apiKey', 'cloud.github.copilotToken',
        'cloud.stripe.secretKey', 'cloud.sendgrid.apiKey', 'cloud.google.apiKey',
        // FP-0419: modern AI / CI-CD key shapes a secret scanner (Caido ai-key/cicd-token checks,
        // trufflehog, gitleaks) matches. Each is exact-shape, seed-derived, non-working, and fingerprint-
        // guarded. See the builder for the per-vendor format.
        'cloud.openai.projectKey', 'cloud.huggingface.token', 'cloud.groq.apiKey',
        'cloud.buildkite.token', 'cloud.circleci.token', 'cloud.github.pat',
        'cloud.github.fineGrainedPat', 'cloud.gitlab.pat', 'cloud.slack.botToken',
        // FP-0558: vendor-EXACT honeytoken shapes so self-hosted gitleaks/trufflehog (not just Caido's
        // loose regexes) emit real findings over the loot. Each is a seeded, inert canary; see the builder.
        'cloud.npm.token', 'cloud.pypi.token', 'cloud.openai.serviceAccountKey', 'payment.cardNumber',
        'secret.jwt',
        'php.version',
        'phpmyadmin.version',
        // The Tomcat servlet-container and JVM versions this host claims — the single source of truth
        // for every Java-stack surface (the manager server table, the catalina.out banner, the Actuator
        // info block, the WEB-INF/web.xml descriptor). Tomcat stays entirely 9.0.x and Java entirely
        // 17.0.x: Tomcat 9 is the `javax.servlet` line (Tomcat 10+ moved to `jakarta.servlet`), so a
        // 10.x banner beside a `javax` stack trace / Servlet 4.0 descriptor is an impossible mix.
        'tomcat.version', 'java.version',
        // The Next.js framework version this host claims — placed in the App-Router shell + the RSC
        // flight as the affected-side version for the React2Shell RSC family (CVE-2025-55182/-55183/
        // -55184). Derived like php.version so every Next.js surface on the deploy agrees.
        'nextjs.version',
        // The Next.js build artifacts this host claims. Real Next.js derives the buildId and the
        // `_next/static` asset content-hashes AT BUILD TIME, so they vary per deployment; hardcoding
        // them fleet-wide (as the shipped shell first did) was a cross-deploy correlation signature.
        // Seeded here so two funnypot Next.js hosts never share an identical buildId/asset hash, while
        // staying denylist-safe (no bare `\b9\d{5}\b`) and inert. buildId is the 21-char nanoid shape;
        // assetHash/appHash are the 16-hex content-hash shape (css+webpack chunk / main-app chunk).
        'nextjs.buildId', 'nextjs.assetHash', 'nextjs.appHash',
        // The Atlassian Confluence version this host claims — one source of truth for every Confluence
        // surface (the `footer-build-information` span on the dashboard/login/server-info pages). The
        // pool sits entirely at or below 8.5.1, so each deploy lands on the affected side of BOTH
        // CVE-2023-22515 (<=8.5.1) and CVE-2023-22527 (<=8.5.3) while still varying per deploy.
        'confluence.version',
        // FP-0409: the FortiOS version this host claims on the SSL-VPN login surfaces (/remote/login,
        // /fpc/app/login) and the future WS CLI banner — one coherent, per-deploy-stable value on the
        // affected side of CVE-2024-55591 (<=7.0.16).
        'fortios.version',
        // FP-0410: the PAN-OS GlobalProtect identity this host claims — version + the matching static-asset
        // ETag (hex build epoch) + Last-Modified, ALL derived from one PANOS_BUILDS index so they can never
        // disagree. panos-scanner / Wapiti decode the asset ETag's hex epoch -> build date -> PAN-OS version;
        // the curated builds are co-generational with the FP-0460 ztp-gate pool. 8-hex etag + dotted version
        // + 4-digit-year Last-Modified all carry <=2-digit / boundary-free runs, so none forms the denied
        // bare 6-digit token.
        'panos.version',
        'panos.etag',
        'panos.lastModified',
        // FP-0383: pre-patch static-asset Last-Modified oracles (OWASP Nettacker *_lastpatcheddate recon).
        // Each vendor's version + lastModified come from ONE BUILDS index (citrixBuild/ivantiBuild) so the
        // vulnerable version and the pre-patch build date can never disagree. The date is a plausible GA
        // build BEFORE the vendor's CVE patch so a scanner declares the host unpatched. No ETag (Nettacker
        // reads Last-Modified only). Dotted/dashed/R version strings + 4-digit-year dates carry no bare
        // 6-digit run. Citrix NetScaler (CVE-2023-4966, patched 2023-10-10); Ivanti Connect Secure
        // (CVE-2023-46805/-2024-21887, patched 2024-01-31).
        'citrix.version',
        'citrix.lastModified',
        'ivanti.version',
        'ivanti.lastModified',
        // The WooCommerce core + payment-plugin versions this host claims — one source of truth for
        // every store surface (the storefront generator meta, the readme `Stable tag:`, the wc-augmented
        // REST index). paymentsVersion and stripeVersion are held on the vulnerable side of their CVEs so
        // the version-fingerprint story agrees with the exploit decoys on the same deploy: WooCommerce
        // Payments 4.8.0–5.6.1 (CVE-2023-28121) and Stripe Gateway <= 7.4.0 (CVE-2023-34000). Dots break
        // every value into <=2-digit runs, so no entry can carry the denied bare 6-digit token.
        'woocommerce.version', 'woocommerce.paymentsVersion', 'woocommerce.stripeVersion',
        // The deploy-stable presentation class prefix, shape `<word>-XXXX`: a seed-picked word from
        // CLASS_PREFIX_WORDS (FP-0283 — no fleet-wide `fp-` regex) plus the historical `|visual|prefix`
        // hex tail. Derived from the SAME NS_VISUAL material VisualPersona uses, so the phpMyAdmin
        // login/gate templates ({{persona.classPrefix}}) and the authed dashboard skin
        // (VisualPersona::classPrefix()) resolve to one identical prefix. See classPrefix().
        'classPrefix',
        'wordpress.version', 'wordpress.theme', 'wordpress.themeVersion',
        // The 32-hex COOKIEHASH real WordPress derives from the site URL and appends to its auth
        // cookie names (`wordpress_logged_in_<hash>`, `wordpress_sec_<hash>`). Seeded here so the
        // decoy-session cookie the wp-login mint sets carries a per-deploy name instead of a fleet-wide
        // fixed literal (the correlation tell a shared cookie name would be). Pure hex has no interior
        // word boundary, so it can never carry the denylist's bare `\b9\d{5}\b` run — no re-roll guard
        // needed (same reasoning as gravatarHash).
        'wordpress.cookieHash',
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
        // FP-0389: the Windows/Active-Directory identity leaked by the NTLM-over-HTTP Type-2 challenge
        // on the Exchange/IIS paths. The canary AD names for funnypot-mainnet correlation — synthetic,
        // deploy-stable, and coherent with the rest of the host (derived from company.slug/domain). All
        // ASCII and digit-safe by construction (the Type-2 packs them verbatim; osBuild is dotted into
        // <=5-digit runs so no entry carries the denied bare 6-digit token).
        'windows.netbiosDomain', 'windows.netbiosComputer', 'windows.dnsDomain',
        'windows.dnsComputer', 'windows.dnsForest', 'windows.osBuild',
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

    // The region pool AND its ElastiCache short-code map in ONE table (keys = the regions the deploy
    // picks from, values = AWS's actual `*.cache.amazonaws.com` endpoint token for each). The region
    // pick draws over array_keys() of this map, so cloud.aws.regionCode is a total lookup that can never
    // miss (no `?? ''` default). These codes are NOT mechanically derivable from the region name
    // (`ap-southeast-1` → `apse1`, not `apso1`), hence an explicit table. Key order is load-bearing:
    // SubSeed::pick indexes array_values(array_keys(...)), so reordering these keys reseeds every
    // deploy's region — keep the historical order.
    private const AWS_REGION_CODES = [
        'us-east-1' => 'use1', 'us-east-2' => 'use2', 'us-west-1' => 'usw1', 'us-west-2' => 'usw2',
        'eu-west-1' => 'euw1', 'eu-west-2' => 'euw2', 'eu-central-1' => 'euc1',
        'ap-southeast-1' => 'apse1', 'ap-southeast-2' => 'apse2', 'ap-northeast-1' => 'apne1',
        'ca-central-1' => 'cac1', 'sa-east-1' => 'sae1',
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
            // Draw the region ONCE (over the map's keys, same order/tag as before ⇒ byte-identical to
            // the historical pick), then derive its short code by a total lookup — no second draw.
            'cloud.aws.region' => $region = self::pick(array_keys(self::AWS_REGION_CODES), $seed, 'aws_region'),
            'cloud.aws.regionCode' => self::AWS_REGION_CODES[$region],

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

            // FP-0419: modern AI / CI-CD key shapes. base62/hex bodies carry no interior word boundary,
            // so a bare 6-digit CRS-id run (\b9\d{5}\b) cannot form in them; only the two url-safe-base64
            // shapes whose '-'/'_' can bound a run are re-roll-guarded (guardedB64Key). All seed-derived,
            // non-working, exact-shape so a secret scanner bites.
            // OpenAI project key: 'sk-proj-' + 74 + the constant 'T3BlbkFJ' infix + 74 [A-Za-z0-9_-].
            // The T3BlbkFJ infix is what gitleaks/trufflehog require (not just Caido's {40,}).
            'cloud.openai.projectKey' => self::openaiProjectKey($seed),
            // HuggingFace user access token: 'hf_' + 34 LETTERS (gitleaks hf_(?i:[a-z]{34}); letters are a
            // subset of Caido/trufflehog's [A-Za-z0-9], and a digitless body can never form a 9ddddd run).
            'cloud.huggingface.token' => 'hf_' . self::alphaRun($seed, 'hf_k', 34),
            // Groq Cloud API key: 'gsk_' + 52 [A-Za-z0-9].
            'cloud.groq.apiKey' => 'gsk_' . self::base62($seed, 'groq_k', 52),
            // BuildKite user token: 'bkua_' + 40 hex.
            'cloud.buildkite.token' => 'bkua_' . substr(self::h($seed, 'bk_k'), 0, 40),
            // CircleCI personal token: 40 hex (presented as `circle-token: <40hex>` / CIRCLE_TOKEN=).
            'cloud.circleci.token' => substr(self::h($seed, 'circle_k'), 0, 40),
            // GitHub classic PAT: 'ghp_' + 36 [A-Za-z0-9].
            'cloud.github.pat' => 'ghp_' . self::base62($seed, 'ghp_k', 36),
            // GitHub fine-grained PAT: 'github_pat_' + 82 [A-Za-z0-9] (base62 subset of [A-Za-z0-9_]).
            'cloud.github.fineGrainedPat' => 'github_pat_' . self::base62($seed, 'ghpat_k', 82),
            // GitLab PAT: 'glpat-' + 20 [A-Za-z0-9_-].
            'cloud.gitlab.pat' => self::guardedB64Key($seed, 'glpat_k', 'glpat-', 20),
            // Slack bot token, VENDOR-EXACT: 'xoxb-' + {11 digits} '-' {12 digits} '-' {24 [A-Za-z0-9]}
            // (gitleaks/trufflehog `xoxb-\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24}`; also matches Caido's looser
            // rule). A \b9\d{5}\b run cannot form: each digit group is one \w run of >=11 digits, so the only
            // word boundaries are at its ends — a leading 9 is followed by >5 digits with no interior \b.
            'cloud.slack.botToken' => 'xoxb-' . self::digits($seed, 'slack_g1', 11) . '-'
                . self::digits($seed, 'slack_g2', 12) . '-' . self::base62($seed, 'slack_s', 24),
            // npm automation token: 'npm_' + 36 [A-Za-z0-9] (gitleaks `npm_[a-z0-9]{36}` is case-insensitive).
            'cloud.npm.token' => self::guardedAlnumKey($seed, 'npm_k', 'npm_', 36),
            // PyPI upload token: 'pypi-' + the constant macaroon prefix gitleaks/trufflehog require, then a
            // url-safe-base64 body. 'AgEIcHlwaS5vcmc' is base64 of the literal "\x02\x01\x08pypi.org" header.
            'cloud.pypi.token' => self::pypiToken($seed),
            // OpenAI service-account key: 'sk-svcacct-' + body + the 'T3BlbkFJ' infix gitleaks requires + body.
            'cloud.openai.serviceAccountKey' => self::openaiPrefixedKey($seed, 'sk-svcacct-', 'openai_svc'),
            // Luhn-valid 16-digit card canary (payments config leak). Seeded, inert, never a well-known test
            // number. One contiguous 16-digit run => no interior \b, so \b9\d{5}\b cannot match (asserted).
            'payment.cardNumber' => self::luhnCard($seed, 'card_k'),

            'secret.jwt' => substr(self::h($seed, 'jwt_secret'), 0, 64),

            // The PHP interpreter version this host claims — the single source of truth for the
            // version shown on any PHP-identity surface (phpinfo, an X-Powered-By the deploy derives
            // from the same persona), so two surfaces never advertise different PHP versions. Derived
            // from the same slug|domain material productVersion() uses, so field() and
            // productVersion('php') always agree.
            'php.version' => self::pickProductVersion($slug, $domain, 'php'),

            // The phpMyAdmin application version this host claims — advertised on the login/gate
            // footer. Derived like php.version so field() and productVersion('phpmyadmin') can never
            // drift. Distinct from the MySQL server version the authed dashboard banner shows: those
            // are two different products and a real phpMyAdmin shows both, so they need not be equal.
            'phpmyadmin.version' => self::pickProductVersion($slug, $domain, 'phpmyadmin'),

            // The Tomcat + JVM versions this host claims, one source of truth for every Java-stack
            // surface. Derived like php.version so field() and productVersion('tomcat'|'java') agree.
            // Tomcat is 9.0.x only (keeps the whole stack on the `javax.servlet`/Servlet 4.0 line) and
            // Java is 17.0.x only, one simple X.Y.Z form used verbatim by every surface (no `+NN` build
            // suffix on one surface and not another).
            'tomcat.version' => self::pickProductVersion($slug, $domain, 'tomcat'),
            'java.version' => self::pickProductVersion($slug, $domain, 'java'),

            // The Next.js version this host claims — the single source of truth for the version shown
            // in the App-Router shell + the RSC flight. Derived like phpmyadmin.version so field() and
            // productVersion('nextjs') never drift. Every entry in the pool is strictly BELOW its
            // release line's patched version (CVE-2025-55182/-55183/-55184), so any deploy lands on
            // the affected side while still varying per deploy (the anti-fingerprint property).
            'nextjs.version' => self::pickProductVersion($slug, $domain, 'nextjs'),

            // Per-deploy Next.js build artifacts (see FIELDS note). Seeded so the buildId + asset
            // hashes decorrelate across funnypot Next.js deploys instead of being fleet-wide constants.
            'nextjs.buildId' => self::nextBuildId($seed),
            'nextjs.assetHash' => self::nextAssetHash($seed, 'nextjs_asset'),
            'nextjs.appHash' => self::nextAssetHash($seed, 'nextjs_app'),

            // The Confluence version this host claims — the single source of truth for the
            // `footer-build-information` span on every Confluence surface. Derived like php.version so
            // field() and productVersion('confluence') never drift; the pool is entirely <=8.5.1 so the
            // rendered version is always on the affected side of CVE-2023-22515 and -22527.
            'confluence.version' => self::pickProductVersion($slug, $domain, 'confluence'),
            'fortios.version' => self::pickProductVersion($slug, $domain, 'fortios'),
            // FP-0410: the PAN-OS GlobalProtect version + its static-asset ETag/Last-Modified, all from ONE
            // PANOS_BUILDS index (panosBuild) so the version, the hex build epoch, and the RFC-1123 date
            // round-trip to the same build and never drift across the portal + the four asset decoys.
            'panos.version' => self::panosBuild($slug, $domain)['version'],
            'panos.etag' => sprintf('%08x', self::panosBuild($slug, $domain)['epoch']),
            'panos.lastModified' => gmdate('D, d M Y H:i:s', self::panosBuild($slug, $domain)['epoch']) . ' GMT',

            // FP-0383: the Citrix NetScaler / Ivanti Connect Secure vulnerable version + pre-patch build
            // date, each from ONE BUILDS index so version<->date round-trip to the same entry (no drift).
            'citrix.version' => self::citrixBuild($slug, $domain)['version'],
            'citrix.lastModified' => gmdate('D, d M Y H:i:s', self::citrixBuild($slug, $domain)['epoch']) . ' GMT',
            'ivanti.version' => self::ivantiBuild($slug, $domain)['version'],
            'ivanti.lastModified' => gmdate('D, d M Y H:i:s', self::ivantiBuild($slug, $domain)['epoch']) . ' GMT',

            // The WooCommerce core + payment-plugin versions this host claims — the single source of
            // truth for every store surface. Derived like php.version so field() and productVersion()
            // never drift. The payments/stripe pools sit entirely on the vulnerable side of their CVEs
            // (see the pool comments), so a version fingerprinter and the CVE decoys agree per deploy.
            'woocommerce.version' => self::pickProductVersion($slug, $domain, 'woocommerce'),
            'woocommerce.paymentsVersion' => self::pickProductVersion($slug, $domain, 'woocommerce-payments'),
            'woocommerce.stripeVersion' => self::pickProductVersion($slug, $domain, 'woocommerce-stripe'),

            // The deploy-stable class prefix, identical to VisualPersona's, so the phpMyAdmin login
            // page and the authed dashboard render one coherent class vocabulary. See classPrefix().
            'classPrefix' => self::classPrefix($seed),

            // The WordPress core version, active theme and theme version this host claims — the single
            // source of truth for the front-door markers a WP fingerprinter reads (generator meta plus
            // versioned wp-includes/wp-content asset links). Core version is derived like php.version so
            // every tier claiming a WP version for this deploy agrees; theme name/version are seed-picked
            // the same way, keeping the whole WordPress surface coherent per deployment.
            'wordpress.version' => self::pickProductVersion($slug, $domain, 'wordpress'),
            'wordpress.theme' => self::pick(self::WP_THEMES, $seed, 'wp_theme'),
            'wordpress.themeVersion' => self::pickProductVersion($slug, $domain, 'wp-theme'),
            // WordPress's COOKIEHASH is md5(site_url); the honeypot has no real site URL, so this is a
            // seed-derived 32-hex stand-in of the same shape, deploy-stable so the wp-login mint and the
            // /wp-admin gate resolve one identical cookie name for a deployment.
            'wordpress.cookieHash' => md5(self::h($seed, 'wp_cookiehash')),
        ];

        // The Windows/AD identity (FP-0389), derived from the SAME slug/domain as the rest of the host
        // so the leaked domain is coherent with the persona, deploy-stable, and distinct per deploy.
        // NetBIOS names are [A-Z0-9], <=15 chars; the DNS names and the dotted osBuild carry no bare
        // 6-digit run, so the NTLM Type-2 that packs them is denylist-safe by construction.
        $winNetbiosDomain = substr((string) preg_replace('/[^A-Z0-9]/', '', strtoupper($slug)), 0, 15);
        $winComputer = substr(
            self::pick(['EXCH', 'MAIL', 'CAS'], $seed, 'win_computer_role')
            . sprintf('%02d', SubSeed::index($seed, SubSeed::NS_PERSONA, 'win_computer_idx', 99) + 1),
            0,
            15
        );
        $winDnsDomain = self::pick(['corp.' . $domain, $slug . '.internal'], $seed, 'win_dns_domain');
        $fields['windows.netbiosDomain'] = $winNetbiosDomain;
        $fields['windows.netbiosComputer'] = $winComputer;
        $fields['windows.dnsDomain'] = $winDnsDomain;
        $fields['windows.dnsComputer'] = strtolower($winComputer) . '.' . $winDnsDomain;
        $fields['windows.dnsForest'] = self::registrableParent($winDnsDomain);
        // A small pool of Windows Server builds, each dotted into <=5-digit runs (no bare 9ddddd token).
        $fields['windows.osBuild'] = self::pick(['10.0.17763', '10.0.20348', '10.0.14393'], $seed, 'win_os_build');

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
        // Plausible recent phpMyAdmin application releases — the version shown on the login footer.
        // One per deploy; a real version number is not a detector signature (same posture as the
        // php/mysql/wordpress pools — the anti-fingerprint property is per-deploy variation).
        'phpmyadmin' => [
            '5.2.2',
            '5.2.1',
            '5.2.0',
            '5.1.4',
            '5.1.3',
        ],
        // Apache Tomcat 9.0.x patch releases only — the whole Java persona stays on the Servlet 4.0 /
        // `javax.servlet` line (Tomcat 10+ is `jakarta.servlet`), so mixing a 10.x major in would
        // contradict the descriptor/stack-trace namespace. Dots break every value into <=2-digit runs,
        // so no entry can carry the denied bare 6-digit token.
        'tomcat' => [
            '9.0.85',
            '9.0.83',
            '9.0.80',
            '9.0.75',
            '9.0.71',
        ],
        // OpenJDK/Temurin 17.0.x LTS releases only — one simple X.Y.Z form shared by every Java surface
        // (HTML manager column, catalina.out JVM line, Actuator JSON), never a `+NN` build suffix on one
        // surface and not another. Dots break every value into <=2-digit runs (denylist-safe).
        'java' => [
            '17.0.11',
            '17.0.10',
            '17.0.9',
            '17.0.8',
            '17.0.7',
        ],
        // Next.js releases for the App-Router "React2Shell" RSC CVE family — CVE-2025-55182 (RCE,
        // CVSS 10.0), -55184 (DoS), -55183 (Server-Function source exposure). Each entry is strictly
        // below its line's PATCHED release (15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7 per
        // GHSA-9qr9-h5gf-34mp and vercel.com/changelog/cve-2025-55182), so every deploy renders an
        // affected-side version. A real semver is not a detector signature; per-deploy variation is
        // the anti-fingerprint property (same posture as the php/mysql/wordpress pools).
        'nextjs' => [
            '15.5.4',
            '15.4.6',
            '15.3.4',
            '15.2.3',
            '16.0.5',
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
        // Atlassian Confluence Data Center/Server releases, all <=8.5.1 so every entry lands on the
        // affected side of CVE-2023-22515 (<=8.5.1, fixed 8.5.2) AND CVE-2023-22527 (<=8.5.3, fixed
        // 8.5.4), and every value matches the 22515 version-footer regex scanners grep for. Dots break
        // each into <=2-digit runs, so no entry carries the denied bare 6-digit token. Per-deploy
        // variation is the anti-fingerprint property (same posture as the php/tomcat pools).
        'confluence' => [
            '8.5.1',
            '8.5.0',
            '8.4.2',
            '8.3.2',
            '8.2.3',
        ],
        // FortiOS releases on the affected side of CVE-2024-55591 — FortiOS 7.0.0-7.0.16 ONLY (per
        // Fortinet FG-IR-24-535; FortiOS 7.2.x is "Not affected" — only FortiProxy 7.2.x is, and this page
        // claims FortiGate/FortiOS). Dotted into <=2-digit runs, so no entry carries the denied bare
        // 6-digit token.
        'fortios' => [
            '7.0.16',
            '7.0.14',
            '7.0.13',
            '7.0.12',
            '7.0.11',
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
        // WooCommerce core releases in the 8.x–9.x era — advertised on the storefront generator meta,
        // the readme `Stable tag:`, and the wc-augmented REST index. One per deploy; a real version
        // number is not a detector signature (same posture as the wordpress/php pools).
        'woocommerce' => [
            '8.5.1',
            '8.6.1',
            '8.7.0',
            '9.0.2',
            '9.1.4',
        ],
        // WooCommerce Payments releases held STRICTLY inside the CVE-2023-28121 affected range
        // (4.8.0–5.6.1) and never a patched sub-release (4.8.2/4.9.1/5.0.4/5.1.3/5.2.2/5.3.1/5.4.1/
        // 5.5.2/5.6.2 are excluded), so the payments-plugin readme version agrees with the auth-bypass
        // decoy on the same deploy. Dots keep every value <=2-digit-run (denylist-safe).
        'woocommerce-payments' => [
            '5.6.1',
            '5.5.1',
            '5.4.0',
            '4.9.0',
            '4.8.1',
        ],
        // WooCommerce Stripe Gateway releases at or below 7.4.0 — the CVE-2023-34000 affected side
        // (patched 7.4.1), so the stripe-plugin readme version backs the pay-for-order IDOR decoy on
        // the same deploy. Dots keep every value <=2-digit-run (denylist-safe).
        'woocommerce-stripe' => [
            '7.4.0',
            '7.3.0',
            '7.2.0',
            '7.1.0',
            '7.0.0',
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
     * FP-0410: curated PAN-OS GA version -> build-epoch pairs, re-derived from the PUBLIC PAN-OS release
     * record (NOT a copy of Wapiti's 222-row version-table — golden rule / clean-room). Each epoch is the
     * approximate documented GA date (UTC midnight) of a real GA version; `panos.etag`/`panos.lastModified`
     * are both derived from the SAME entry so the asset ETag's hex epoch decodes back to this build date and
     * a version fingerprinter (panos-scanner / Wapiti mod_paloalto) reads one coherent version. The set is
     * co-generational with the FP-0460 ztp-gate pool (10.1/10.2/11.0/11.1): FP-0564 makes the ztp-gate read
     * {{persona.panos.version}}, so one deploy shows ONE PAN-OS version across the ztp-gate, the login.esp
     * portal and the four asset ETags. Every entry is on the affected side of CVE-2025-0108 (the ztp-gate's
     * own auth-bypass CVE) AND the marquee GlobalProtect RCE CVE-2024-3400 (10.2/11.0/11.1; 10.1 is the one
     * ztp-only build). The older 8.1/9.1 builds (CVE-2020-2021-only) were dropped — a single shared version
     * on a CVE-2025-0108 ztp-gate must itself be CVE-2025-0108-affected. Every rendered value (8-hex etag,
     * dotted version, 4-digit-year RFC-1123 date) is free of the denied bare 6-digit run.
     */
    private const PANOS_BUILDS = [
        ['version' => '10.1.0', 'epoch' => 1618876800],  // 2021-04-20
        ['version' => '10.2.0', 'epoch' => 1637107200],  // 2021-11-17
        ['version' => '11.0.0', 'epoch' => 1668470400],  // 2022-11-15
        ['version' => '11.1.0', 'epoch' => 1700092800],  // 2023-11-16
    ];

    /**
     * One PANOS_BUILDS entry for this deploy — keyed like pickProductVersion so the triple is deploy-stable
     * and per-seed. Returns ['version'=>string,'epoch'=>int].
     *
     * @return array{version:string,epoch:int}
     */
    private static function panosBuild(string $slug, string $domain): array
    {
        $idx = (int) (hexdec(substr(hash('sha256', $slug . '|' . $domain . '|panos-build'), 0, 8)) % count(self::PANOS_BUILDS));

        return self::PANOS_BUILDS[$idx];
    }

    /**
     * FP-0383: real vulnerable Citrix NetScaler ADC/Gateway builds — all BEFORE the CVE-2023-4966
     * (Citrix Bleed) fix of 2023-10-10 (fixes 13.1-49.15 / 14.1-8.50 / 13.0-92.19). The epoch is a
     * plausible GA build date for that line; version + date come from the same entry so the
     * /epa/scripts/win/nsepa_setup.exe Last-Modified decodes back to a coherent unpatched build.
     *
     * @var non-empty-list<array{version:string,epoch:int}>
     */
    private const CITRIX_BUILDS = [
        ['version' => '13.1-48.47', 'epoch' => 1684108800],  // 2023-05-15
        ['version' => '13.0-90.12', 'epoch' => 1681084800],  // 2023-04-10
        ['version' => '14.1-4.42',  'epoch' => 1691366400],  // 2023-08-07
    ];

    /**
     * FP-0383: real vulnerable Ivanti Connect Secure builds — all BEFORE the CVE-2023-46805 /
     * CVE-2024-21887 fix of 2024-01-31. Serves the /dana-na/css/ds.js Last-Modified.
     *
     * @var non-empty-list<array{version:string,epoch:int}>
     */
    private const IVANTI_BUILDS = [
        ['version' => '22.3R1',   'epoch' => 1687219200],  // 2023-06-20
        ['version' => '9.1R18.3', 'epoch' => 1694476800],  // 2023-09-12
        ['version' => '22.5R2.1', 'epoch' => 1698105600],  // 2023-10-24
    ];

    /**
     * One CITRIX_BUILDS entry for this deploy — keyed like panosBuild so the version+date is deploy-stable.
     *
     * @return array{version:string,epoch:int}
     */
    private static function citrixBuild(string $slug, string $domain): array
    {
        $idx = (int) (hexdec(substr(hash('sha256', $slug . '|' . $domain . '|citrix-build'), 0, 8)) % count(self::CITRIX_BUILDS));

        return self::CITRIX_BUILDS[$idx];
    }

    /**
     * One IVANTI_BUILDS entry for this deploy — keyed like panosBuild so the version+date is deploy-stable.
     *
     * @return array{version:string,epoch:int}
     */
    private static function ivantiBuild(string $slug, string $domain): array
    {
        $idx = (int) (hexdec(substr(hash('sha256', $slug . '|' . $domain . '|ivanti-build'), 0, 8)) % count(self::IVANTI_BUILDS));

        return self::IVANTI_BUILDS[$idx];
    }

    /**
     * Neutral CSS-namespace words a real front-end ships (styled-components/Material/Element-style
     * prefixes, plain app/ui namespaces). Lowercase [a-z]{2,3}: no digit (so a word can never extend
     * the hex tail into a denied digit run), no product word (pma/wp — those skins keep their own
     * literal vocabularies by design), and NEVER `fp` — the funnypot signature this pool exists to
     * retire (FP-0283). Denylist-clean against every reachable word × tail × suffix (RenderHtmlHelpersTest
     * exhaustive sweep). `scan()` is a whole-needle stripos, so `el`/`sc` being substrings of the
     * denylist literals `paranoia-level`/`inbound_anomaly_score` can never make a served page hit.
     * Public so the tests can sweep it.
     *
     * @var non-empty-list<string>
     */
    public const CLASS_PREFIX_WORDS = ['ui', 'app', 'st', 'mx', 'tpl', 'cx', 'el', 'ns', 'vx', 'ux', 'mat', 'sc'];

    /**
     * The deploy-stable presentation class prefix (shape `<word>-XXXX`). The WORD is seed-picked from
     * CLASS_PREFIX_WORDS (FP-0283) so no fleet-wide `fp-` regex exists any more; the 4-hex TAIL keeps
     * the historical `|visual|prefix` digest byte-for-byte, so only the word moves from what this deploy
     * shipped. Deliberately hashes the SAME `|visual|prefix`/`prefix-word` material under NS_VISUAL, NOT
     * this class's `|persona|` tag — so the value is byte-identical to the prefix VisualPersona ships.
     * That is what makes the phpMyAdmin login/gate templates (which read this via {{persona.classPrefix}})
     * and the authed dashboard (which reads VisualPersona::classPrefix()) present one coherent class
     * vocabulary; VisualPersona::classPrefix() delegates here so there is a single source of truth.
     */
    private static function classPrefix(int $seed): string
    {
        return SubSeed::pick(self::CLASS_PREFIX_WORDS, $seed, SubSeed::NS_VISUAL, 'prefix-word')
            . '-' . substr(SubSeed::digest($seed, SubSeed::NS_VISUAL, 'prefix'), 0, 4);
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
        return SubSeed::digest($seed, SubSeed::NS_PERSONA, $field);
    }

    /**
     * Deterministic dictionary pick for a field.
     *
     * @param array<int,string> $dict
     */
    private static function pick(array $dict, int $seed, string $field): string
    {
        return SubSeed::pick(array_values($dict), $seed, SubSeed::NS_PERSONA, $field);
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
     * FP-0419: prefix + `len` url-safe-base64 chars ([A-Za-z0-9_-]), re-rolled past the fingerprint
     * denylist's bare 6-digit run — a '-'/'_' in the prefix or body can bound one (unlike a pure base62
     * body, which has no interior word boundary). Used for the '-'-bearing shapes (sk-proj-, glpat-).
     */
    private static function guardedB64Key(int $seed, string $field, string $prefix, int $len): string
    {
        for ($round = 0; ; $round++) {
            $f = $round === 0 ? $field : $field . '|r' . $round;
            $body = substr(self::base64url((string) hex2bin(
                self::h($seed, $f) . self::h($seed, $f . '2') . self::h($seed, $f . '3') . self::h($seed, $f . '4')
            )), 0, $len);
            // A trailing '-' breaks a \b-anchored scanner rule (glpat-/trufflehog): '-' is \W, so the
            // closing \b can't land after it and {20,} can't backtrack below the required length. Re-roll.
            if (substr($body, -1) === '-') {
                continue;
            }
            $value = $prefix . $body;
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /**
     * FP-0419: OpenAI project key — 'sk-proj-' + 74 + the constant 'T3BlbkFJ' infix + 74 url-safe-base64.
     * The infix is what gitleaks/trufflehog's openai rules require; the overall body still satisfies
     * Caido's 'sk-proj-[A-Za-z0-9_-]{40,}'. Re-rolled past the denied digit run and a trailing '-'.
     */
    private static function openaiProjectKey(int $seed): string
    {
        for ($round = 0; ; $round++) {
            $s = $round === 0 ? '' : '|r' . $round;
            $a = substr(self::base64url((string) hex2bin(
                self::h($seed, 'openai_proj_a' . $s) . self::h($seed, 'openai_proj_a2' . $s) . self::h($seed, 'openai_proj_a3' . $s)
            )), 0, 74);
            $b = substr(self::base64url((string) hex2bin(
                self::h($seed, 'openai_proj_b' . $s) . self::h($seed, 'openai_proj_b2' . $s) . self::h($seed, 'openai_proj_b3' . $s)
            )), 0, 74);
            $value = 'sk-proj-' . $a . 'T3BlbkFJ' . $b;
            if (substr($b, -1) !== '-' && !self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /** FP-0558: `len` decimal digits from the seed, first digit non-zero (a numeric id never leads with 0). */
    private static function digits(int $seed, string $field, int $len): string
    {
        $hex = self::h($seed, $field);
        $round = 1;
        while (strlen($hex) < $len * 2) {
            $hex .= self::h($seed, $field . $round);
            $round++;
        }
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $d = (int) hexdec(substr($hex, $i * 2, 2)) % 10;
            if ($i === 0 && $d === 0) {
                $d = 1 + ((int) hexdec(substr($hex, 0, 2)) % 9);
            }
            $out .= (string) $d;
        }

        return $out;
    }

    /** FP-0558: `prefix` + `len` [A-Za-z0-9] from the seed, re-rolled past the denied bare-6-digit run. */
    private static function guardedAlnumKey(int $seed, string $field, string $prefix, int $len): string
    {
        for ($round = 0; ; $round++) {
            $f = $round === 0 ? $field : $field . '|r' . $round;
            $value = $prefix . self::base62($seed, $f, $len);
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /**
     * FP-0558: PyPI upload token — 'pypi-' + the constant macaroon prefix 'AgEIcHlwaS5vcmc' (base64 of the
     * literal "\x02\x01\x08pypi.org" header that gitleaks/trufflehog's pypi rule requires) + a url-safe-base64
     * body. Re-rolled past a trailing '-' (would break a \b-anchored rule) and the denied digit run.
     */
    private static function pypiToken(int $seed): string
    {
        for ($round = 0; ; $round++) {
            $s = $round === 0 ? '' : '|r' . $round;
            $body = substr(self::base64url((string) hex2bin(
                self::h($seed, 'pypi_a' . $s) . self::h($seed, 'pypi_a2' . $s) . self::h($seed, 'pypi_a3' . $s) . self::h($seed, 'pypi_a4' . $s)
            )), 0, 130);
            $value = 'pypi-AgEIcHlwaS5vcmc' . $body;
            if (substr($body, -1) !== '-' && !self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /**
     * FP-0558: an OpenAI-family key with a parameterized prefix (e.g. 'sk-svcacct-') carrying the 'T3BlbkFJ'
     * infix gitleaks/trufflehog require. Mirrors openaiProjectKey; re-rolled past a trailing '-' and the run.
     */
    private static function openaiPrefixedKey(int $seed, string $prefix, string $tag): string
    {
        for ($round = 0; ; $round++) {
            $s = $round === 0 ? '' : '|r' . $round;
            $a = substr(self::base64url((string) hex2bin(
                self::h($seed, $tag . '_a' . $s) . self::h($seed, $tag . '_a2' . $s) . self::h($seed, $tag . '_a3' . $s)
            )), 0, 74);
            $b = substr(self::base64url((string) hex2bin(
                self::h($seed, $tag . '_b' . $s) . self::h($seed, $tag . '_b2' . $s) . self::h($seed, $tag . '_b3' . $s)
            )), 0, 74);
            $value = $prefix . $a . 'T3BlbkFJ' . $b;
            if (substr($b, -1) !== '-' && !self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /**
     * FP-0558: a Luhn-valid 16-digit Visa-range card canary (for a payments-config leak). Seeded + inert +
     * per-deploy; the '45' lead keeps it in a real Visa range while avoiding the well-known 42xx/41xx/40xx
     * test BINs, so it is never a recognisable test number. One contiguous 16-digit run has no interior word
     * boundary, so \b9\d{5}\b can never match (re-roll guard kept for symmetry; asserted in tests).
     */
    private static function luhnCard(int $seed, string $field): string
    {
        for ($round = 0; ; $round++) {
            $f = $round === 0 ? $field : $field . '|r' . $round;
            $hex = self::h($seed, $f) . self::h($seed, $f . '2');
            $body = '45';
            for ($i = 0; strlen($body) < 15; $i++) {
                $body .= (string) ((int) hexdec(substr($hex, $i * 2, 2)) % 10);
            }
            $body = substr($body, 0, 15);
            $pan = $body . self::luhnCheckDigit($body);
            if (!self::hitsDeniedDigits($pan)) {
                return $pan;
            }
        }
    }

    /** The Luhn check digit for `$digits` when it is appended as the rightmost digit of the full number. */
    private static function luhnCheckDigit(string $digits): string
    {
        $sum = 0;
        $len = strlen($digits);
        for ($i = 0; $i < $len; $i++) {
            $d = (int) $digits[$i];
            // After the check digit is appended, $digits[$i] sits at position (len+1-i) from the right; it is
            // doubled when that position is even, i.e. when $i is even for a 15-digit body.
            if (($len - $i) % 2 === 1) {
                $d *= 2;
                if ($d > 9) {
                    $d -= 9;
                }
            }
            $sum += $d;
        }

        return (string) ((10 - ($sum % 10)) % 10);
    }

    /** FP-0419: `len` letters ([A-Za-z]) from the seed — a digitless run (no 6-digit-run risk), for the
     *  HuggingFace token whose gitleaks rule is letters-only. */
    private static function alphaRun(int $seed, string $field, int $len): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $hex = self::h($seed, $field);
        $round = 1;
        while (strlen($hex) < $len * 2) {
            $hex .= self::h($seed, $field . $round);
            $round++;
        }
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= $alphabet[(int) hexdec(substr($hex, $i * 2, 2)) % 52];
        }

        return $out;
    }

    /**
     * True if a rendered secret carries the fingerprint gate's denied bare-6-digit token
     * (\b9\d{5}\b). A served body that trips it is classified as canned, so the boundary-prone
     * generators re-derive until clean — terminating in one or two rounds almost surely.
     */
    private static function hitsDeniedDigits(string $value): bool
    {
        return SubSeed::hitsDeniedDigits($value);
    }

    /**
     * A Next.js buildId — 21 chars of a lowercase-alnum nanoid alphabet, the shape real Next.js emits
     * for `NEXT_BUILD_ID` and the `/_next/static/<buildId>/` asset path. Kept lowercase-alnum (no `-`/
     * `_`) to match the shipped representative and to keep the string free of interior word boundaries,
     * so the only `\b`s are the token's own edges. Seeded per deploy so two funnypot Next.js hosts never
     * share a buildId (the cross-deploy correlation tell this fixes). Re-rolls on the denied digit run.
     */
    private static function nextBuildId(int $seed): string
    {
        $alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
        $n = strlen($alphabet);
        for ($round = 0; ; $round++) {
            // One 64-hex digest covers 21 chars (needs 42 hex); the round tag re-derives on a re-roll.
            $h = self::h($seed, $round === 0 ? 'nextjs_build' : 'nextjs_build|r' . $round);
            $out = '';
            for ($i = 0; $i < 21; $i++) {
                $out .= $alphabet[(int) hexdec(substr($h, $i * 2, 2)) % $n];
            }
            if (!self::hitsDeniedDigits($out)) {
                return $out;
            }
        }
    }

    /**
     * A 16-hex Next.js `_next/static` asset content-hash (css / webpack / main-app chunk fingerprint),
     * seeded per deploy — hardcoding it fleet-wide was a cross-deploy correlation signature. The hash
     * sits between `-`/`/` and `.`/`/` in the asset path, so its edges are the same word boundaries the
     * bare value has; re-roll on the denied digit run (`\b9\d{5}\b`) guards the edge case where the
     * value itself is `9` + five digits, and hitsDeniedDigits over the bare token is therefore exact.
     */
    private static function nextAssetHash(int $seed, string $field): string
    {
        for ($round = 0; ; $round++) {
            $value = substr(self::h($seed, $round === 0 ? $field : $field . '|r' . $round), 0, 16);
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
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

    /**
     * The forest/tree root a single-domain AD advertises for $dnsDomain: drop the leftmost label when a
     * dotted parent remains (corp.acme.com -> acme.com), else keep the domain itself (acme.internal is
     * already its own forest root). A forest is never rooted at a bare TLD label, so the parent is only
     * taken when it still has a dot.
     */
    private static function registrableParent(string $dnsDomain): string
    {
        $dot = strpos($dnsDomain, '.');
        if ($dot === false) {
            return $dnsDomain;
        }
        $parent = substr($dnsDomain, $dot + 1);

        return strpos($parent, '.') === false ? $dnsDomain : $parent;
    }

    /** Replicated from Compiler\ProductIdentity::slug — kept local so Support never depends on Compiler. */
    private static function slug(string $s): string
    {
        $s = strtolower(trim($s));
        $s = preg_replace('/[^a-z0-9]+/', '-', $s) ?? '';

        return trim($s, '-');
    }
}
