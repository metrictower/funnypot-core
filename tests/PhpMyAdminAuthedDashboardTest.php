<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\Honeytoken;
use Funnypot\RequestContext;
use Funnypot\Support\VisualPersona;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * Phase B: the authed phpMyAdmin decoy dashboard. Once a request presents a verified `s=1` cookie the
 * gate renders a fabricated "breached database" through the shared core PhpMyAdminSkin. Pins:
 *  - the left tree lists all five mock tables; the grid shows the selected one;
 *  - `?table=` selects among a whitelist (unknown/absent -> users), never reflecting the raw value;
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

    /** The name=value pair a browser sends back, built directly from an s=1 cookie (no mint round-trip). */
    private function authedCookie(): string
    {
        $setCookie = (new Honeytoken(self::KEY))->cookie('phpMyAdmin', 's=1', '/phpmyadmin');
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    /** @return \Funnypot\SynthesizedResponse|null */
    private function authedGet(TemplateAttackEmulator $em, string $query = '')
    {
        return $em->emulate(new RequestContext('GET', '/phpmyadmin/index.php', $query, ['Cookie' => $this->authedCookie()]));
    }

    // --- table tree + selection -------------------------------------------------------------

    public function test_default_view_is_the_users_table(): void
    {
        $r = $this->authedGet($this->emulator([$this->gateRule()]));

        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        // Every mock table appears in the left tree.
        foreach (['users', 'password_resets', 'api_keys', 'sessions', 'orders'] as $t) {
            self::assertStringContainsString('>' . $t . '</li>', $r->body, $t . ' in tree');
        }
        // The users grid is the default main view: its column headers are present.
        foreach (['id', 'username', 'email', 'created_at'] as $col) {
            self::assertStringContainsString('<th>' . $col . '</th>', $r->body);
        }
    }

    public function test_table_query_selects_api_keys_grid(): void
    {
        $r = $this->authedGet($this->emulator([$this->gateRule()]), 'table=api_keys');

        self::assertNotNull($r);
        // api_keys-specific columns (owner_name / api_key / last_used_at) prove the selection took.
        foreach (['id', 'owner_name', 'api_key', 'created_at', 'last_used_at'] as $col) {
            self::assertStringContainsString('<th>' . $col . '</th>', $r->body);
        }
        // Not the users grid's distinctive column.
        self::assertStringNotContainsString('<th>username</th>', $r->body);
    }

    public function test_unknown_table_query_falls_back_to_users(): void
    {
        $r = $this->authedGet($this->emulator([$this->gateRule()]), 'table=..%2Fetc%2Fpasswd&x=1');

        self::assertNotNull($r);
        self::assertStringContainsString('<th>username</th>', $r->body, 'unknown table must degrade to users');
        // The raw crafted value is never reflected into the output.
        self::assertStringNotContainsString('etc', $r->body);
        self::assertStringNotContainsString('passwd', $r->body);
    }

    public function test_each_table_renders_its_own_loot_columns(): void
    {
        $expected = [
            'users' => 'email',
            'password_resets' => 'reset_token',
            'api_keys' => 'api_key',
            'sessions' => 'last_activity',
            'orders' => 'amount',
        ];
        $em = $this->emulator([$this->gateRule()]);
        foreach ($expected as $table => $signatureCol) {
            $r = $this->authedGet($em, 'table=' . $table);
            self::assertNotNull($r, $table);
            self::assertStringContainsString('<th>' . $signatureCol . '</th>', $r->body, $table . ' signature column');
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
        $b = $this->authedGet($this->emulator([$this->gateRule()], self::SEED + 7));

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
        // keeps the user rows coherent with the site identity around them for every seed.
        $rule = $this->gateRule();
        unset($rule['decoy-session']['domain']);

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
