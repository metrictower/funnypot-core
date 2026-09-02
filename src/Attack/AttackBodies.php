<?php

declare(strict_types=1);

namespace Funnypot\Core\Attack;

use Funnypot\Core\Support\SubSeed;

/**
 * The single source of truth for the incidental (non-marker) content of the TIER-2 static
 * attack-class response bodies, de-fingerprinted per deploy (FP-0279). The SQLi error frame's
 * path/username/line/near fragment and the SSTI/CRS-xss decline pages' titles + copy were fleet
 * constants copied byte-identical across every deploy — a cross-deploy correlation tell — so this
 * class derives them as a pure function of the deploy identity seed (via the FP-0276 SubSeed
 * primitive, namespace SubSeed::NS_ATTACK) while keeping every EXPLOIT-CONFIRMATION MARKER intact.
 *
 * MARKERS ARE NEVER EMITTED HERE. The load-bearing 1064 sentence (MYSQL_1064), the `SQL syntax`
 * expect: pin, the `' at line 1` tail and the page skeletons are LITERAL authored template text; this
 * class only fills the incidental slots that surround them. So no seed — 0 (the compile-time
 * assertMarkers render) or any deploy — can drop a marker: the marker is authored, never derived.
 *
 * DETERMINISM. Every derivation is `SubSeed::index/pick($seed, NS_ATTACK, FIELD)` over the constants
 * here — no clock, CSPRNG, request byte, or the 64-bit-only child seed (SubSeed::int) ever enters, so
 * within a deploy the bytes are stable and across deploys they vary. The seed handed in is the deploy
 * IDENTITY seed (DirectiveRenderer::identitySeed()), the same seed {{persona.*}} rides. This class
 * never reads PersonaIdentity itself — DirectiveRenderer hands in the resolved persona company name
 * (page titles) and company slug (the /var/www/<slug>/ docroot), so the error frame's docroot is
 * byte-identical to the docroot phpinfo (60-phpinfo.yaml:40) and every /var/www/{{persona.company.slug}}/
 * log line already claim. A future template that claims a DIFFERENT docroot or advertises a mysqli
 * extension must update this helper too.
 *
 * PHP 7.3-safe: htmlspecialchars()/str_replace()/preg_match()/in_array() and SubSeed only.
 */
final class AttackBodies
{
    /** The SQLi frame slots — the closed form set after `sqli.`. */
    public const SQLI_SLOTS = ['prefix', 'near', 'suffix'];

    /** The decline-page kinds — the KIND after a `page.title:`/`page.body:` form. */
    public const PAGE_KINDS = ['home', 'search'];

    /** The decline-page slots — the form after `page.`. */
    public const PAGE_SLOTS = ['title', 'body'];

    /**
     * The load-bearing MySQL 1064 sentence (up to and including the opening `near '` quote). NOT
     * emitted by this class — it is literal template text; pinned here so tests can assert every SQLi
     * template carries it verbatim OUTSIDE any directive, and so the class documents which bytes are
     * the marker. The dialect word stays `MySQL` (not a MySQL/MariaDB pick): sqlmap's primary MySQL
     * fingerprint is `SQL syntax.*?MySQL`, so varying it would trade scanner-confirmation strength for
     * ~1 bit of entropy. No server version is inserted — real MySQL error 1064 never carries one, so a
     * version here would be a new fleet-wide honeypot tell.
     */
    public const MYSQL_1064 = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '";

    /**
     * PHP display-mode warning frames — PDO ONLY. The deploy's phpinfo (60-phpinfo.yaml:50-51) lists
     * pdo_mysql + pdo_pgsql and NO mysqli, so a mysqli_query() frame would contradict the host's own
     * extension list on ~half of deploys. WARNING (not a Fatal PDOException) because attack-sqli is a
     * status-200 rule and a Fatal frame is served with 500 by real PHP — status cannot be varied per
     * deploy by a directive. A WARNING frame implies the app runs the explicit legacy
     * PDO::ERRMODE_WARNING mode (PDO defaults to exceptions on PHP 8.0/8.1+, and the persona pool
     * claims 7.4.33–8.3.6) — a stated realism assumption, plausible for a legacy codebase. Byte-exact
     * to PHP's html_errors=On display shape, including the TWO spaces after `</b>:`.
     * Index 0 is the bare frame (F0); 1 is PDO::query() (F1); 2 is PDOStatement::execute() (F2).
     */
    private const FRAME_PREFIX = [
        '',
        "<br />\n<b>Warning</b>:  PDO::query(): SQLSTATE[42000]: Syntax error or access violation: 1064 ",
        "<br />\n<b>Warning</b>:  PDOStatement::execute(): SQLSTATE[42000]: Syntax error or access violation: 1064 ",
    ];

    /**
     * Plausible offending-token fragments a broken string literal leaves near the parse error — static
     * literals, NEVER attacker bytes (the frame carries no capture). The always-empty `near ''` is
     * deliberately excluded: it is the fleet signature this ticket dissolves, and keeping it would let
     * some deploys reproduce today's exact bytes. Doubled-quote fragments are excluded as rare-looking.
     */
    private const NEAR_POOL = ["'", "' LIMIT 1", "1'", "' ORDER BY id DESC", "%'", "')", "' AND 1"];

    /** Source sub-directory of the docroot the fake frame blames. `public/` mirrors phpinfo's docroot. */
    private const DIR_POOL = ['public/', 'app/', 'includes/', 'inc/', 'lib/', 'src/', 'classes/'];

    /** Source file the fake frame blames. */
    private const FILE_POOL = ['db.php', 'database.php', 'Database.php', 'functions.php', 'query.php', 'model.php', 'search.php', 'products.php'];

    /** Home decline-page titles (SSTI decline). Every option embeds `{c}` (the escaped company name). */
    private const HOME_TITLES = ['{c}', '{c} — Home', 'Home — {c}', 'Welcome to {c}', '{c} | Home'];

    /** Home decline-page inner-body copy. Inert English/HTML, no digits, no `{{`. */
    private const HOME_BODIES = [
        '<p>Welcome.</p>',
        '<h1>Welcome</h1>',
        '<h1>{c}</h1><p>Welcome.</p>',
        '<p>Welcome to {c}.</p>',
        '<h1>Welcome to {c}</h1><p>Please sign in to continue.</p>',
        '<p>This site is currently under maintenance. Please check back later.</p>',
    ];

    /** Search decline-page titles (CRS-xss decline). Every option embeds `{c}`. */
    private const SEARCH_TITLES = ['Search — {c}', '{c} — Search results', 'Search | {c}', '{c} Search', 'Search results — {c}'];

    /** Search decline-page inner-body copy. Inert English/HTML, no digits, no `{{`. */
    private const SEARCH_BODIES = [
        '<h1>Search results</h1><p>No results found for your query.</p>',
        '<h1>Search</h1><p>Your search returned no results.</p>',
        '<h2>Search results</h2><p>No matching items were found.</p>',
        '<h1>Results</h1><p>Sorry, nothing matched your search.</p>',
        '<h1>Search {c}</h1><p>No results found.</p>',
    ];

    private function __construct()
    {
    }

    /**
     * Resolve one `{{attack.*}}` form (the whole spec AFTER `attack.`) to its per-deploy value; null
     * for an unknown form (the fail-safe every closed directive family uses; the compile lint rejects
     * it first). $company/$slug are the deploy's persona fields, handed in by DirectiveRenderer — this
     * class never reads PersonaIdentity itself.
     *
     *   sqli.prefix | sqli.near | sqli.suffix     the SQLi error-frame slots (B1/B2/B3)
     *   page.title:home | page.body:home          the SSTI decline page (B5)
     *   page.title:search | page.body:search      the CRS-xss decline page (B4)
     */
    public static function resolve(string $spec, int $seed, string $company, string $slug): ?string
    {
        if (strpos($spec, 'sqli.') === 0) {
            return self::sqli($seed, substr($spec, 5), $slug);
        }
        if (strpos($spec, 'page.') === 0) {
            $bits = explode(':', substr($spec, 5), 2);

            return self::page($seed, $bits[1] ?? '', $bits[0], $company);
        }

        return null;
    }

    /**
     * One SQLi error-frame slot. The prefix/suffix are both derived from the SAME `sqli|frame` draw, so
     * a deploy's frame is internally consistent (a bare frame has an empty prefix AND suffix; a warning
     * frame has both halves of the same warning). The `near` fragment is drawn independently and is
     * always non-empty. Returns null for an unknown slot (the compile lint rejects it first).
     *
     * @param string $slug the deploy's persona company.slug — the /var/www/<slug>/ docroot component
     */
    public static function sqli(int $seed, string $slot, string $slug): ?string
    {
        if (!in_array($slot, self::SQLI_SLOTS, true)) {
            return null;
        }
        if ($slot === 'near') {
            return SubSeed::pick(self::NEAR_POOL, $seed, SubSeed::NS_ATTACK, 'sqli|near');
        }
        // frame: 0 => F0 bare (rarest); 1..3 => F1 PDO::query(); 4..5 => F2 PDOStatement::execute().
        $frame = SubSeed::index($seed, SubSeed::NS_ATTACK, 'sqli|frame', 6);
        if ($frame === 0) {
            return ''; // bare frame: no prefix, no suffix — only the near fragment differs from today.
        }
        if ($slot === 'prefix') {
            return $frame <= 3 ? self::FRAME_PREFIX[1] : self::FRAME_PREFIX[2];
        }
        // suffix: " in <b>/var/www/<slug>/<dir><file></b> on line <b>N</b><br />" — rooted at the SAME
        // docroot phpinfo advertises, NEVER a fixed /var/www/html/ (which would be an in-deploy
        // contradiction and a new fleet-constant substring on ~5/6 of deploys).
        $dir = SubSeed::pick(self::DIR_POOL, $seed, SubSeed::NS_ATTACK, 'sqli|dir');
        $file = SubSeed::pick(self::FILE_POOL, $seed, SubSeed::NS_ATTACK, 'sqli|file');
        $line = 10 + SubSeed::index($seed, SubSeed::NS_ATTACK, 'sqli|line', 240); // 10..249, never a 6-digit run
        $slugSegment = self::slugSafe($slug) ? $slug . '/' : ''; // hostile/empty slug -> /var/www/<dir><file>

        return ' in <b>/var/www/' . $slugSegment . $dir . $file . '</b> on line <b>' . $line . '</b><br />';
    }

    /**
     * One decline-page slot (title or inner body) for a KIND. The company name is HTML-escaped
     * (ENT_QUOTES|ENT_HTML5) so a future persona-pool change can never inject markup. Returns null for
     * an unknown kind/slot (the compile lint rejects it first).
     */
    public static function page(int $seed, string $kind, string $slot, string $company): ?string
    {
        if (!in_array($kind, self::PAGE_KINDS, true) || !in_array($slot, self::PAGE_SLOTS, true)) {
            return null;
        }
        if ($kind === 'home') {
            $pool = $slot === 'title' ? self::HOME_TITLES : self::HOME_BODIES;
        } else {
            $pool = $slot === 'title' ? self::SEARCH_TITLES : self::SEARCH_BODIES;
        }
        $chosen = SubSeed::pick($pool, $seed, SubSeed::NS_ATTACK, 'page|' . $slot . '|' . $kind);
        $c = htmlspecialchars($company, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return str_replace('{c}', $c, $chosen);
    }

    /**
     * Compile-time closed-form check (called from all three compilers' assertKnownDirectives). True for
     * exactly `sqli.{prefix,near,suffix}` and `page.{title,body}:{home,search}`.
     */
    public static function isKnownForm(string $spec): bool
    {
        if (strpos($spec, 'sqli.') === 0) {
            return in_array(substr($spec, 5), self::SQLI_SLOTS, true);
        }
        if (strpos($spec, 'page.') === 0) {
            $bits = explode(':', substr($spec, 5), 2);

            return in_array($bits[0], self::PAGE_SLOTS, true)
                && isset($bits[1]) && in_array($bits[1], self::PAGE_KINDS, true);
        }

        return false;
    }

    /**
     * The SQLi frame's five raw draws — TEST-ONLY, for the cross-deploy variance sweep (never on the
     * served path). Exposed so a test can assert distinctness on the draw TUPLE rather than the
     * assembled body (the bare frame collapses dir/file/line, so a body-level count under-reports).
     *
     * @return array{frame:int,near:string,dir:string,file:string,line:int}
     */
    public static function sqliDraws(int $seed): array
    {
        return [
            'frame' => SubSeed::index($seed, SubSeed::NS_ATTACK, 'sqli|frame', 6),
            'near' => SubSeed::pick(self::NEAR_POOL, $seed, SubSeed::NS_ATTACK, 'sqli|near'),
            'dir' => SubSeed::pick(self::DIR_POOL, $seed, SubSeed::NS_ATTACK, 'sqli|dir'),
            'file' => SubSeed::pick(self::FILE_POOL, $seed, SubSeed::NS_ATTACK, 'sqli|file'),
            'line' => 10 + SubSeed::index($seed, SubSeed::NS_ATTACK, 'sqli|line', 240),
        ];
    }

    /**
     * A slug is safe to embed in the docroot path if it is non-empty and carries no HTML-significant
     * byte, brace, or whitespace/CR/LF. Belt-and-braces — every shipped persona slug is [a-z0-9]+, so
     * this fallback is never reachable with the shipped pool.
     */
    private static function slugSafe(string $slug): bool
    {
        return $slug !== '' && preg_match('/[<>&"\'{}\s]/', $slug) !== 1;
    }
}
