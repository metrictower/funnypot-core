<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Behavior\DecoyTables;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * Phase B: the authed phpMyAdmin decoy dashboard. Once a request presents a verified authenticated
 * cookie the gate renders a fabricated "breached database" through the shared core PhpMyAdminSkin. Pins:
 *  - the left tree lists THIS deploy's seeded table story (DecoyTables, FP-0282); the grid shows the
 *    selected one; the tree and the `?table=` whitelist are one seeded set (they cannot drift);
 *  - `?table=` accepts exactly this deploy's served names (unknown/absent/foreign -> the users-kind
 *    default), never reflecting the raw value;
 *  - one deploy seed => byte-stable output (a fleet-coherent identity), a different seed diverges;
 *  - fabricated cells are HTML-escaped;
 *  - a rendered body carrying an upstream-detector signature FAILS CLOSED to the login page (the
 *    runtime FingerprintGuard net), never serving it and never throwing.
 */
final class PhpMyAdminAuthedDashboardTest extends TestCase
{
    private const KEY = 'S3cr3t-Decoy-Signing-Key-must-never-leak';

    private const LOGIN_STUB = '<html>LOGIN_STUB_GATE</html>';

    private const SEED = 484348449122915112;

    /** @return array<string,mixed> */
    private function gateRule(string $domain = 'example.test', int $rows = 5): array
    {
        return [
            'id' => 'decoy-gate-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 200,
            'match' => [
                ['in' => 'method', 'regex' => '^GET$'],
                ['in' => 'path', 'regex' => '^/phpmyadmin/index\.php$'],
            ],
            'response' => ['headers' => [], 'body' => self::LOGIN_STUB],
            'behavior' => 'decoy-session',
            'decoy-session' => [
                'mode' => 'gate',
                'cookie_name' => 'phpMyAdmin',
                'cookie_path' => '/phpmyadmin',
                'domain' => $domain,
                'table_key' => 'users',
                'rows' => $rows,
            ],
        ];
    }

    private function emulator(array $rules, ?int $personaSeed = self::SEED): TemplateAttackEmulator
    {
        return new TemplateAttackEmulator($rules, [], null, null, [], $personaSeed, self::KEY);
    }

    /** The name=value pair a browser sends back, minted at the SAME deploy seed the emulator gates with
     *  (no mint round-trip). The seed must match the emulator's persona seed or the gate fails closed. */
    private function authedCookie(int $seed = self::SEED): string
    {
        $setCookie = (new DecoySession(self::KEY, $seed))->mintCookie('phpMyAdmin', '/phpmyadmin');
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    /** @return \Funnypot\Core\SynthesizedResponse|null */
    private function authedGet(TemplateAttackEmulator $em, string $query = '', int $seed = self::SEED)
    {
        return $em->emulate(new RequestContext('GET', '/phpmyadmin/index.php', $query, ['Cookie' => $this->authedCookie($seed)]));
    }

    // --- table tree + selection -------------------------------------------------------------

    /** The fixed (non-timestamp) signature column that uniquely proves a given kind's grid rendered. */
    private const KIND_SIGNATURE = [
        'users' => 'email',
        'password_resets' => 'reset_token',
        'api_keys' => 'api_key',
        'sessions' => 'last_activity',
        'orders' => 'amount',
        'secrets' => 'value',
    ];

    public function test_default_view_is_the_users_table(): void
    {
        $r = $this->authedGet($this->emulator([$this->gateRule()]));

        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        // The left tree lists EXACTLY this deploy's seeded table story (FP-0282): every served name is
        // present, and no other pool name is.
        $served = DecoyTables::names(self::SEED);
        foreach ($served as $t) {
            self::assertStringContainsString('>' . $t . '</li>', $r->body, $t . ' in tree');
        }
        foreach (DecoyTables::allNames() as $n) {
            if (!in_array($n, $served, true)) {
                self::assertStringNotContainsString('>' . $n . '</li>', $r->body, $n . ' must NOT appear (not this deploy\'s name)');
            }
        }
        // The default main view is the users-kind table, headed by its seeded name, showing this
        // deploy's users column labels (the {ts:*} slot follows the deploy's timestamp convention).
        self::assertStringContainsString('>' . DecoyTables::defaultName(self::SEED) . '</h1>', $r->body, 'heading = default table name');
        foreach (DecoyTables::columns(self::SEED, 'users') as $col) {
            self::assertStringContainsString('<th>' . $col . '</th>', $r->body);
        }
        // FP-0283: the authed body carries the seeded `<word>-XXXX` class prefix on both sides and never
        // the retired fleet-constant `fp-` (the login/gate templates + this skin resolve one prefix).
        $prefix = VisualPersona::fromSeed(self::SEED)->classPrefix();
        self::assertStringContainsString('class="' . $prefix . '-topbar"', $r->body, 'authed body uses the seeded class prefix');
        self::assertStringNotContainsString('class="fp-', $r->body, 'no legacy fp- class prefix in the served authed body');
    }

    public function test_table_query_selects_api_keys_grid(): void
    {
        // Precondition (SEED is a constant): the api_keys kind is present at SEED (drawn as `api_tokens`).
        $apiKeysName = DecoyTables::nameOf(self::SEED, 'api_keys');
        self::assertNotNull($apiKeysName, 'api_keys kind must be present at SEED');

        $r = $this->authedGet($this->emulator([$this->gateRule()]), 'table=' . $apiKeysName);

        self::assertNotNull($r);
        // api_keys-specific columns prove the selection took (labels are this deploy's, incl. its {ts:*}).
        foreach (DecoyTables::columns(self::SEED, 'api_keys') as $col) {
            self::assertStringContainsString('<th>' . $col . '</th>', $r->body);
        }
        // Not the users grid's distinctive column.
        self::assertStringNotContainsString('<th>username</th>', $r->body);
    }

    public function test_unknown_table_query_falls_back_to_users(): void
    {
        $em = $this->emulator([$this->gateRule()]);
        $whitelist = DecoyTables::whitelist(self::SEED);

        // A traversal payload is never a served name -> users-kind default; the raw value is never reflected.
        $r = $this->authedGet($em, 'table=..%2Fetc%2Fpasswd&x=1');
        self::assertNotNull($r);
        self::assertStringContainsString('<th>username</th>', $r->body, 'unknown table must degrade to users');
        self::assertStringContainsString('<th>email</th>', $r->body);
        self::assertStringNotContainsString('etc', $r->body);
        self::assertStringNotContainsString('passwd', $r->body);

        // Today's literal names are NOT this deploy's names (at SEED users->members, secrets->vault), so
        // `table=secrets` must fall back to the users grid (no `value` column), NOT open a secrets grid.
        // Fails at baseline where 'secrets' was a hardcoded whitelist key.
        self::assertArrayNotHasKey('secrets', $whitelist, 'precondition: SEED does not serve a table literally named "secrets"');
        $r2 = $this->authedGet($em, 'table=secrets');
        self::assertNotNull($r2);
        self::assertStringContainsString('<th>username</th>', $r2->body);
        self::assertStringNotContainsString('<th>value</th>', $r2->body, "literal 'secrets' must not open the secrets grid");

        // A name a DIFFERENT deploy draws but this one does not also falls back to users.
        $foreign = null;
        foreach (DecoyTables::allNames() as $n) {
            if (!isset($whitelist[$n])) {
                $foreign = $n;
                break;
            }
        }
        self::assertNotNull($foreign, 'there must be a pool name this deploy does not serve');
        $r3 = $this->authedGet($em, 'table=' . $foreign);
        self::assertNotNull($r3);
        self::assertStringContainsString('<th>username</th>', $r3->body, "a foreign deploy's name must fall back to users");
    }

    public function test_each_table_renders_its_own_loot_columns(): void
    {
        $em = $this->emulator([$this->gateRule()]);
        foreach (DecoyTables::forDeploy(self::SEED) as $t) {
            $signatureCol = self::KIND_SIGNATURE[$t['kind']];
            $r = $this->authedGet($em, 'table=' . $t['name']);
            self::assertNotNull($r, $t['name']);
            self::assertStringContainsString('<th>' . $signatureCol . '</th>', $r->body, $t['name'] . ' (' . $t['kind'] . ') signature column');
        }
    }

    public function test_secrets_table_renders_flag_tokens(): void
    {
        // Drive the SHIPPED decoy row count (attack rule 102 authors rows: 8) so this fixture can no
        // longer pass while production duplicates labels at 8 rows. The secrets table is served under
        // THIS deploy's seeded name.
        $r = $this->authedGet($this->emulator([$this->gateRule('example.test', 8)]), 'table=' . DecoyTables::nameOf(self::SEED, 'secrets'));

        self::assertNotNull($r);
        // The secrets grid's own columns prove the selection took.
        foreach (['id', 'name', 'value'] as $col) {
            self::assertStringContainsString('<th>' . $col . '</th>', $r->body);
        }
        // The marquee lure: inert CTF-sentinel flag tokens sit in the value column, behind the login.
        self::assertStringContainsString('FLAG.{', $r->body);
        self::assertStringContainsString('}.GALF', $r->body);
        self::assertMatchesRegularExpression('/FLAG\.\{[0-9a-f]{40}\}\.GALF/', $r->body);

        // No label repeats in the rendered table — every `name` cell is distinct, so there is never
        // a second, contradictory value for the same label (e.g. two different ctf_flag values).
        foreach (['ctf_flag', 'root_flag', 'service_flag', 'admin_token', 'backup_token', 'db_password', 'signing_key', 'api_secret'] as $label) {
            self::assertLessThanOrEqual(1, substr_count($r->body, '<td>' . $label . '</td>'), $label . ' must appear at most once');
        }
    }

    public function test_flag_absent_pre_auth(): void
    {
        // No cookie -> the login stub renders, never the authed breached-DB body, so no flag leaks
        // before the attacker walks the mock login.
        $r = $this->emulator([$this->gateRule()])->emulate(
            new RequestContext('GET', '/phpmyadmin/index.php', 'table=secrets')
        );

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB, $r->body);
        self::assertStringNotContainsString('FLAG.{', $r->body);
    }

    public function test_whitelist_accepts_exactly_this_deploys_table_set_over_many_seeds(): void
    {
        // The end-to-end "advertised == accepted" law through the real gate path (cookie, guard, skin):
        // for many deploys, every served name opens its own kind's grid, every non-served pool name falls
        // back to the users grid, and the tree always equals names($seed). Fails at baseline (helper
        // absent + a fixed six-name whitelist that accepts foreign names like the literal `secrets`).
        for ($i = 0; $i < 24; $i++) {
            $seed = PersonaIdentity::seedFromMaterial('sweep-' . $i);
            $em = $this->emulator([$this->gateRule()], $seed);
            $served = DecoyTables::names($seed);

            // Every served name opens its own kind's grid.
            foreach (DecoyTables::forDeploy($seed) as $t) {
                $r = $this->authedGet($em, 'table=' . $t['name'], $seed);
                self::assertNotNull($r, "seed {$i} name {$t['name']}");
                // The tree advertises exactly the served set.
                foreach ($served as $n) {
                    self::assertStringContainsString('>' . $n . '</li>', $r->body, "seed {$i}: tree must list {$n}");
                }
                self::assertStringContainsString('<th>' . self::KIND_SIGNATURE[$t['kind']] . '</th>', $r->body, "seed {$i}: {$t['name']} must open its {$t['kind']} grid");
            }

            // Every pool name this deploy does NOT serve falls back to the users grid, headed by the
            // deploy's default (users-kind) name.
            $default = DecoyTables::defaultName($seed);
            foreach (DecoyTables::allNames() as $n) {
                if (in_array($n, $served, true)) {
                    continue;
                }
                $r = $this->authedGet($em, 'table=' . $n, $seed);
                self::assertNotNull($r, "seed {$i} foreign {$n}");
                self::assertStringContainsString('<th>username</th>', $r->body, "seed {$i}: foreign {$n} must fall back to users");
                self::assertStringContainsString('>' . $default . '</h1>', $r->body, "seed {$i}: fallback heading = default name");
            }
        }
    }

    // --- persona coherence ------------------------------------------------------------------

    public function test_same_deploy_seed_is_byte_stable(): void
    {
        $a = $this->authedGet($this->emulator([$this->gateRule()], self::SEED));
        $b = $this->authedGet($this->emulator([$this->gateRule()], self::SEED));

        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, 'one deploy seed must render an identical dashboard every fetch');
    }

    public function test_different_deploy_seed_diverges(): void
    {
        $a = $this->authedGet($this->emulator([$this->gateRule()], self::SEED));
        $b = $this->authedGet($this->emulator([$this->gateRule()], self::SEED + 7), '', self::SEED + 7);

        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertNotSame($a->body, $b->body, 'a different deploy is a different fake site');
    }

    public function test_version_banner_and_brand_present(): void
    {
        $r = $this->authedGet($this->emulator([$this->gateRule()]));

        self::assertNotNull($r);
        self::assertStringContainsString('phpMyAdmin', $r->body);
        self::assertStringContainsString('Server version:', $r->body);
    }

    public function test_unconfigured_domain_defaults_to_the_persona_domain(): void
    {
        // A gate rule that authors no `domain` must render fabricated emails on the SAME persona domain
        // the skin's topbar/db/version identity uses — never a giveaway literal like example.com. This
        // keeps the user rows coherent with the site identity around them for every seed. The compiler
        // normalizes an omitted `domain` to '' (not absent), so '' is the realistic case to pin.
        $rule = $this->gateRule();
        $rule['decoy-session']['domain'] = '';

        $r = $this->authedGet($this->emulator([$rule], self::SEED));
        self::assertNotNull($r);

        $personaDomain = VisualPersona::fromSeed(self::SEED)->domain();
        self::assertStringContainsString('Server: ' . $personaDomain, $r->body, 'topbar uses the persona domain');
        self::assertStringContainsString('@' . $personaDomain, $r->body, 'user emails must share the persona domain');
        self::assertStringNotContainsString('@example.com', $r->body, 'must not fall back to a giveaway literal');
    }

    // --- escaping + fail-closed -------------------------------------------------------------

    public function test_fabricated_cells_are_html_escaped(): void
    {
        // An authored domain carrying markup must never reach the body un-escaped (defense in depth:
        // the skin escapes every slot cell). '<script>' has no directive braces, so it round-trips
        // into the fabricated email cell where the skin must neutralize it.
        $r = $this->authedGet($this->emulator([$this->gateRule('<script>evil.test')]));

        self::assertNotNull($r);
        self::assertStringNotContainsString('<script>', $r->body);
        self::assertStringContainsString('&lt;script&gt;', $r->body);
    }

    public function test_fingerprint_unsafe_body_fails_closed_to_login_page(): void
    {
        // Sanity: the token we inject really is on the runtime denylist, so this test is meaningful.
        self::assertNotSame([], FingerprintGuard::fromPackage()->scan('user@900111.example.test'));

        // An authored domain that makes a fabricated email cell spell a bare CRS-rule-id run
        // (\b9\d{5}\b) must make the whole authed body fail closed to the login page — never served.
        $r = $this->authedGet($this->emulator([$this->gateRule('900111.example.test')]));

        self::assertNotNull($r);
        self::assertSame(self::LOGIN_STUB, $r->body, 'a fingerprint-unsafe body must decline to the login page');
        self::assertStringNotContainsString('phpMyAdmin', $r->body);
        self::assertStringNotContainsString('900111', $r->body);
    }
}
