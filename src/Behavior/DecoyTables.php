<?php

declare(strict_types=1);

namespace Funnypot\Core\Behavior;

use Funnypot\Core\Support\SubSeed;

/**
 * The ONE source of the authed phpMyAdmin decoy's "breached database" table story (FP-0282). A deploy's
 * table set — which mock tables its left tree lists, what each is named, its column labels, the display
 * order, and whether one optional table is dropped — is a pure function of the deploy seed, so the fixed
 * six-name fleet constant (users, password_resets, api_keys, sessions, orders, secrets) is no longer a
 * cross-fleet correlation handle. Within a deploy the story is byte-identical every render; across
 * deploys it varies.
 *
 * ONE-SOURCE LAW (the load-bearing invariant). forDeploy() returns the whole story as an ordered list of
 * {kind, name, columns}. Everything else is a PROJECTION of that one array:
 *   - names()     = the served left-tree order (array_column forDeploy 'name');
 *   - whitelist() = served name => canonical kind — the `?table=` accept-set, built by folding
 *                   forDeploy(), NEVER a second literal list.
 * Because the tree and the whitelist are two projections of ONE pure function of ONE seed, no request,
 * seed, or code path can make the tree advertise a name the whitelist rejects or accept a name the tree
 * does not show. A `?table=` value this deploy serves is honored; any other value (another deploy's
 * names, today's literals when not drawn this deploy, a traversal payload) falls back to the users-kind
 * default exactly as an unknown value does — the raw value is only ever compared to keys, never
 * reflected.
 *
 * WHAT IS THE LURE vs WHAT IS THE SKELETON. The row CONTENT (the fabricated cells and the inert
 * FLAG.{40hex}.GALF sentinel) is drawn by FakeRecords keyed on the INVARIANT canonical kind and the
 * authored table_key ('users'), never on a served name — so the loot is byte-identical to today at every
 * seed. Only the story SKELETON (names, column labels, tree order, the one dropped optional table)
 * varies. Column COUNT and ORDER are FakeRecords' positional row shapes (FakeRecords.php:47,65,83,107,
 * 125,151) and must NEVER change; only the {ts:*} timestamp label slots vary, all through ONE per-deploy
 * convention so a deploy's schema is internally consistent.
 *
 * DETERMINISM. Every varied byte is SubSeed::index/pick under NS_DECOY only; SubSeed::int (64-bit-only)
 * is never called here, and no clock/CSPRNG/request byte enters. Pools are letters/underscore only, so
 * no free-form string and no denied-digit re-roll can occur; pairwise disjoint across kinds so usort by
 * strcmp is tie-free (the disjointness pin in DecoyTablesTest is therefore load-bearing for order
 * determinism on PHP 7.3's unstable usort).
 *
 * ZERO COMPILED DRIFT. The table story is render-time: no compiler stores a table name, and the compiled
 * manifest is link-derived from the authed body, which carries NO href/action/fetch/url target for the
 * phpMyAdmin panel (ManifestBuilder::skinLinks/scanBody at STUB_SEED=1) — a seeded tree/label set (all
 * letters/underscore, none spelling url/href/action) cannot introduce a link, so the manifest and
 * check-drift stay byte-identical. WARNING for future siblings: this render-time-only property is
 * specific to the phpMyAdmin panel. The WordPress authed body ALREADY emits href targets into the
 * manifest at STUB_SEED=1, so any future seeding of a linked tree (e.g. `?table=<name>` anchors, or the
 * wp-admin menu) WOULD become a compiled-manifest change under FP-0263 and demand a deterministic
 * recompile — do not assume the phpMyAdmin precedent transfers.
 *
 * PHP 7.3-safe: plain static methods, arrays, and SubSeed only.
 */
final class DecoyTables
{
    /** The canonical FakeRecords kinds — the INVARIANT keys the row-generator dispatch and the column
     *  shapes are written against. Never served; a served name maps back to one of these. */
    public const KINDS = ['users', 'password_resets', 'api_keys', 'sessions', 'orders', 'secrets'];

    /** Kinds a deploy may omit. users (the default view + the FakeRecords table_key anchor) and secrets
     *  (the FLAG lure) are never dropped. */
    public const OPTIONAL = ['password_resets', 'api_keys', 'sessions', 'orders'];

    /** Per-kind display-name pools. DISJOINT across kinds (tested), so two kinds can never draw one name
     *  and the alphabetical order is always tie-free.
     *
     * @var array<string,list<string>>
     */
    public const NAMES = [
        'users' => ['users', 'app_users', 'members', 'accounts', 'user_accounts'],
        'password_resets' => ['password_resets', 'password_reset_tokens', 'reset_tokens', 'pw_resets', 'user_password_resets'],
        'api_keys' => ['api_keys', 'api_tokens', 'access_tokens', 'apikeys', 'user_api_keys'],
        'sessions' => ['sessions', 'user_sessions', 'login_sessions', 'app_sessions', 'auth_sessions'],
        'orders' => ['orders', 'customer_orders', 'purchases', 'sales_orders', 'order_history'],
        'secrets' => ['secrets', 'app_secrets', 'credentials', 'vault', 'config_secrets'],
    ];

    /** Column labels per kind. COUNT and ORDER are FakeRecords' positional row shapes and must never
     *  change; a `{ts:slot}` token is a timestamp column resolved through the deploy's TS_STYLES row.
     *
     * @var array<string,list<string>>
     */
    public const COLUMNS = [
        'users' => ['id', 'username', 'email', '{ts:created}'],
        'password_resets' => ['email', 'reset_token', '{ts:requested}', '{ts:expires}'],
        'api_keys' => ['id', 'owner_name', 'api_key', '{ts:created}', '{ts:last_used}'],
        'sessions' => ['id', 'username', 'ip', 'last_activity'],
        'orders' => ['order_id', 'customer', 'amount', 'status', '{ts:created}'],
        'secrets' => ['id', 'name', 'value'],
    ];

    /** One timestamp-column convention per deploy (a real schema names its timestamp columns
     *  consistently across its tables).
     *
     * @var list<array<string,string>>
     */
    public const TS_STYLES = [
        ['created' => 'created_at', 'requested' => 'requested_at', 'expires' => 'expires_at', 'last_used' => 'last_used_at'],
        ['created' => 'created', 'requested' => 'requested', 'expires' => 'expires', 'last_used' => 'last_used'],
        ['created' => 'date_created', 'requested' => 'date_requested', 'expires' => 'date_expires', 'last_used' => 'date_last_used'],
        ['created' => 'created_on', 'requested' => 'requested_on', 'expires' => 'expires_on', 'last_used' => 'last_used_on'],
    ];

    private function __construct()
    {
    }

    /**
     * THE table story: an ordered list of {kind, name, columns}, sorted by name (phpMyAdmin lists a
     * database's tables alphabetically, so the order varies only as a consequence of the names). Every
     * other accessor projects this array.
     *
     * @return list<array{kind:string,name:string,columns:list<string>}>
     */
    public static function forDeploy(int $deploySeed): array
    {
        $drop = SubSeed::index($deploySeed, SubSeed::NS_DECOY, 'tables|drop', 8);
        $dropped = $drop < count(self::OPTIONAL) ? self::OPTIONAL[$drop] : null;
        $tsStyle = self::tsStyle($deploySeed);

        $story = [];
        foreach (self::KINDS as $kind) {
            if ($kind === $dropped) {
                continue;
            }
            if (!isset(self::NAMES[$kind]) || !isset(self::COLUMNS[$kind])) {
                throw new \RuntimeException('DecoyTables: kind "' . $kind . '" has no NAMES/COLUMNS pool');
            }
            $story[] = [
                'kind' => $kind,
                'name' => SubSeed::pick(self::NAMES[$kind], $deploySeed, SubSeed::NS_DECOY, 'tables|name|' . $kind),
                'columns' => self::resolveColumns(self::COLUMNS[$kind], $tsStyle),
            ];
        }

        usort($story, static function (array $a, array $b): int {
            return strcmp($a['name'], $b['name']);
        });

        return $story;
    }

    /**
     * The served name => canonical kind map — the `?table=` whitelist. DERIVED from forDeploy(), never a
     * second list.
     *
     * @return array<string,string>
     */
    public static function whitelist(int $deploySeed): array
    {
        $w = [];
        foreach (self::forDeploy($deploySeed) as $t) {
            $w[$t['name']] = $t['kind'];
        }

        return $w;
    }

    /**
     * The served left-tree order — array_column(forDeploy(), 'name').
     *
     * @return list<string>
     */
    public static function names(int $deploySeed): array
    {
        $names = [];
        foreach (self::forDeploy($deploySeed) as $t) {
            $names[] = $t['name'];
        }

        return $names;
    }

    /** The users-kind name — the default/fallback view (users is never dropped). */
    public static function defaultName(int $deploySeed): string
    {
        foreach (self::forDeploy($deploySeed) as $t) {
            if ($t['kind'] === 'users') {
                return $t['name'];
            }
        }

        // Unreachable: users is never in OPTIONAL. Fail loud rather than serve a nameless default.
        throw new \RuntimeException('DecoyTables: users kind unexpectedly absent from the story');
    }

    /**
     * This deploy's column labels for $kind. A caller passes a canonical kind (a whitelist() value); an
     * unknown kind is a programming error, not an unknown ?table= value, so it throws.
     *
     * @return list<string>
     */
    public static function columns(int $deploySeed, string $kind): array
    {
        if (!isset(self::COLUMNS[$kind])) {
            throw new \RuntimeException('DecoyTables: unknown kind "' . $kind . '"');
        }

        return self::resolveColumns(self::COLUMNS[$kind], self::tsStyle($deploySeed));
    }

    /** The served name of $kind on this deploy, or null when the kind is dropped. */
    public static function nameOf(int $deploySeed, string $kind): ?string
    {
        foreach (self::forDeploy($deploySeed) as $t) {
            if ($t['kind'] === $kind) {
                return $t['name'];
            }
        }

        return null;
    }

    /**
     * Every name in every pool — for the hygiene/coherence tests.
     *
     * @return list<string>
     */
    public static function allNames(): array
    {
        $all = [];
        foreach (self::NAMES as $pool) {
            foreach ($pool as $name) {
                $all[] = $name;
            }
        }

        return $all;
    }

    /** @return array<string,string> the timestamp-column convention this deploy uses. */
    private static function tsStyle(int $deploySeed): array
    {
        return self::TS_STYLES[SubSeed::index($deploySeed, SubSeed::NS_DECOY, 'tables|ts', count(self::TS_STYLES))];
    }

    /**
     * Resolve `{ts:slot}` timestamp tokens in a column list against the deploy's TS_STYLES row; every
     * other label passes through verbatim. Column count and order are preserved exactly.
     *
     * @param list<string>          $columns
     * @param array<string,string>  $tsStyle
     * @return list<string>
     */
    private static function resolveColumns(array $columns, array $tsStyle): array
    {
        $out = [];
        foreach ($columns as $col) {
            if (preg_match('/^\{ts:([a-z_]+)\}$/', $col, $m) === 1 && isset($tsStyle[$m[1]])) {
                $out[] = $tsStyle[$m[1]];
                continue;
            }
            $out[] = $col;
        }

        return $out;
    }
}
