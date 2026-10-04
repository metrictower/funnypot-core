<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0465: the modern Atlassian Confluence suite — CVE-2023-22527 (OGNL/SSTI unauth RCE) and
 * CVE-2023-22515 (broken access control -> unauth admin). Both CVSS 10.0, CISA KEV. All surfaces are
 * stateless core decoys: the SSTI command-exec confirmation, the version fingerprint, and the
 * setup-admin form + POST capture. Nothing is evaluated or persisted.
 */
final class ConfluenceModernSuiteTest extends TestCase
{
    // The 22515 version-footer regex scanners grep for (<=8.5.1 is the affected side).
    private const V22515 = '/8\.(0\.[0-4]|1\.[0-4]|2\.[0-3]|3\.[0-2]|4\.[0-2]|5\.[0-1])/';

    /** @var array<string,mixed> */
    private static function index(): array
    {
        return require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    }

    private function engine(string $seed = 's'): Honeypot
    {
        // Mirrors NewPageRoutingTest::saltedInverter: a probe-signature predicate returning true + a
        // fixed render-seed closure are what admit route-tier serving; the trailing seedSalt drives the
        // persona identity. attackEmulation on so the 22527 attack template is live too.
        $cfg = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'fixed'; },
            'coherent',
            Style::REALISTIC,
            'critical',
            65536,
            0,
            0,
            false,
            null,
            null,
            null,
            $seed
        );
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    /** @param array<string,string> $headers */
    private function resp(string $method, string $path, string $query = '', ?string $body = null, array $headers = []): ?object
    {
        return $this->engine()->respond(new RequestContext($method, $path, $query, $headers, $body, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    // ---- CVE-2023-22527 OGNL/SSTI --------------------------------------------------------------

    public function test_22527_command_exec_returns_uid_header(): void
    {
        $payload = "label=\\u0027%2b#request\\u005b\\u0027.KEY_velocity.struts2.context\\u0027\\u005d"
            . ".get(\\u0027com.opensymphony.xwork2.ActionContext.container\\u0027)"
            . ".getInstance(freemarker.template.utility.Execute).exec({\\u0027id\\u0027})";
        $resp = $this->resp('POST', '/template/aui/text-inline.vm', '', $payload, ['Content-Type' => 'application/x-www-form-urlencoded']);
        self::assertNotNull($resp, 'the 22527 endpoint must serve');
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('uid=0(root)', $resp->headers['X-Cmd-Response'] ?? '', 'command-exec confirmation header');
    }

    public function test_22527_payload_is_never_evaluated_or_reflected(): void
    {
        // Inert: only the canned uid header is emitted; no attacker byte reaches the body.
        $payload = 'label=freemarker.template.utility.Execute.exec({\'Zconfsentinel42Z\'})';
        $resp = $this->resp('POST', '/template/aui/text-inline.vm', '', $payload);
        self::assertStringNotContainsString('Zconfsentinel42Z', $this->body($resp), 'no request byte may be reflected');
    }

    public function test_22527_arithmetic_variant_falls_through_to_ssti_numeric(): void
    {
        // The ${a*b} arithmetic confirmation carries no command-exec marker, so 06 declines and the
        // generic SSTI-numeric decoy computes and reflects the product (197*7331 = 1444207).
        $resp = $this->resp('POST', '/template/aui/text-inline.vm', '', 'label=${197*7331}');
        self::assertStringContainsString((string) (197 * 7331), $this->body($resp), 'arithmetic product must be reflected');
    }

    public function test_cve_2022_26134_decoy_stays_intact(): void
    {
        // 05 (the older OGNL CVE) must keep answering its ${...#context...getRuntime} payload.
        $resp = $this->resp('GET', '/', 'x=${(#a=@java.lang.Runtime@getRuntime().exec(\'id\'))}');
        self::assertStringContainsString('uid=0(root)', $resp->headers['X-Cmd-Response'] ?? '');
    }

    // ---- CVE-2023-22515 version fingerprint + setup --------------------------------------------

    public function test_22515_dashboard_discloses_affected_version(): void
    {
        $resp = $this->resp('GET', '/dashboard.action');
        self::assertSame(200, $resp->status ?? null);
        $b = $this->body($resp);
        self::assertStringContainsString("id='footer-build-information'", $b);
        self::assertSame(1, preg_match(self::V22515, $b), 'version must match the 22515 affected-version regex');
    }

    public function test_22515_server_info_resolves_with_setup_flag_param(): void
    {
        // The ?bootstrapStatusProvider...setupComplete=false param is stripped from the route key, so
        // the exploit's param-laden GET resolves to the same server-info HTML page.
        $resp = $this->resp('GET', '/server-info.action', 'bootstrapStatusProvider.applicationConfig.setupComplete=false');
        self::assertSame(200, $resp->status ?? null);
        self::assertSame(1, preg_match(self::V22515, $this->body($resp)));
    }

    public function test_22515_setup_admin_form_is_served(): void
    {
        $resp = $this->resp('GET', '/setup/setupadministrator.action');
        self::assertSame(200, $resp->status ?? null);
        self::assertStringContainsString('Administrator Account', $this->body($resp));
        self::assertStringContainsString('name="password"', $this->body($resp));
    }

    public function test_22515_setup_admin_post_redirects_to_finish(): void
    {
        $resp = $this->resp('POST', '/setup/setupadministrator.action', '', 'username=attacker&password=Pwn123!&email=a@b.c&fullName=A');
        self::assertSame(302, $resp->status ?? null, 'POST must 302 like the real setup wizard');
        self::assertSame('/setup/finishsetup.action', $resp->headers['Location'] ?? null);
    }

    public function test_confluence_version_varies_per_seed_and_stays_affected(): void
    {
        $versions = [];
        foreach (['seedA', 'seedB', 'seedC', 'seedD', 'seedE'] as $seed) {
            $h = $this->engine($seed);
            $b = (string) ($h->respond(new RequestContext('GET', '/dashboard.action', '', [], null, 'x.test'))->body ?? '');
            self::assertSame(1, preg_match(self::V22515, $b), "seed {$seed}: version must stay on the affected side");
            self::assertSame(1, preg_match('#footer-build-information\'>([0-9.]+)<#', $b, $m));
            $versions[$seed] = $m[1];
        }
        self::assertGreaterThan(1, count(array_unique($versions)), 'the version must vary across seeds (per-deploy anti-fingerprint)');
    }
}
