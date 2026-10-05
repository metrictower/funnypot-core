<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Attack;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * FP-0422 (core slice): INtrack IoT-backdoor / worm decoys. Hikvision CVE-2017-7921 config disclosure +
 * Hadoop YARN new-application (route new_page); FatPipe + AntSword backdoors (enrich); Cisco IOS XE implant
 * + Tomcat JSP PUT worm (attack, request-reactive). Honeytoken = deploy-stable persona.user.admin.password
 * (not the literal canary123). Stateful upload storage / reverse-shell capture are app (FP-0566). Fixture:
 * full compiled corpus via Honeypot::respond() with attackEmulation on; engine memoized per seed.
 */
final class IntrackBackdoorWormTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;
    /** @var array<string,Honeypot> */
    private static $engines = [];

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (isset(self::$engines[$seed])) {
            return self::$engines[$seed];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return self::$engines[$seed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    /** @param array<string,string> $headers */
    private function resp(string $method, string $path, string $query = '', array $headers = [], ?string $body = null, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext($method, $path, $query, $headers, $body, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_hikvision_configfile_serves_persona_cred_not_canary(): void
    {
        $seed = 'hostZ';
        $ps = PersonaIdentity::fromSeed(PersonaIdentity::seedFromMaterial($seed));
        $r = $this->resp('GET', '/System/configurationFile', '', [], null, $seed);
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('application/octet-stream', (string) ($r->headers['Content-Type'] ?? ''));
        $b = $this->body($r);
        self::assertStringContainsString('<adminUserName>admin</adminUserName>', $b);
        self::assertStringContainsString('<adminPassword>' . $ps->field('user.admin.password') . '</adminPassword>', $b, 'must leak the persona admin password');
        self::assertStringNotContainsString('canary123', $b, 'must not use the literal canary123');
        self::assertNotNull(simplexml_load_string($b), 'config must be well-formed XML');
    }

    public function test_hadoop_newapp_valid_json(): void
    {
        $r = $this->resp('GET', '/ws/v1/cluster/apps/new-application');
        self::assertSame(200, $r->status ?? null);
        $j = json_decode($this->body($r), true);
        self::assertIsArray($j);
        self::assertSame(1, preg_match('/^application_\d{13}_\d{4}$/', (string) ($j['application-id'] ?? '')), 'app-id shape');
    }

    public function test_fatpipe_loginservlet_json(): void
    {
        $b = $this->body($this->resp('POST', '/fpui/loginServlet', '', [], 'cmuser=admin'));
        self::assertNotNull(json_decode($b));
        self::assertStringContainsString('"loginRes":"success"', $b);
        self::assertStringContainsString('"activeUserName":"cmuser"', $b);
    }

    public function test_antsword_md5(): void
    {
        self::assertStringContainsString('951d11e51392117311602d0c25435d7f', $this->body($this->resp('POST', '/.antproxy.php', '', [], 'x')));
    }

    public function test_cisco_implant_gated_on_auth_header(): void
    {
        $withAuth = $this->resp('GET', '/webui/logoutconfirm.html', 'logon_hash=1', ['Authorization' => '0ff4fbf0ecffa77ce8d3852a29263e263838e9bb']);
        self::assertSame(200, $withAuth->status ?? null);
        self::assertSame(1, preg_match('/^[a-f0-9]{18}\s*$/', $this->body($withAuth)), 'must be an 18-hex implant token');
        // Without the implant Authorization header, the implant 18-hex token must NOT serve.
        $noAuth = $this->resp('GET', '/webui/logoutconfirm.html', 'logon_hash=1');
        self::assertNotSame(1, preg_match('/^[a-f0-9]{18}\s*$/', $this->body($noAuth)), 'no-auth must not get the implant token');
    }

    public function test_tomcat_put_jsp_201_no_reflection_no_storage(): void
    {
        $payload = '<% Runtime.getRuntime().exec("id"); out.println("ZZSHELLZZ"); %>';
        $r = $this->resp('PUT', '/evil9z.jsp', '', [], $payload);
        self::assertSame(201, $r->status ?? null, 'PUT .jsp must be 201 Created');
        self::assertLessThanOrEqual(1, strlen($this->body($r)), 'body must be empty (no storage/echo)');
        self::assertStringNotContainsString('ZZSHELLZZ', $this->body($r), 'uploaded payload must not be reflected');
        // GET of the same .jsp must NOT 201 (method-gated; nothing was stored).
        self::assertNotSame(201, $this->resp('GET', '/evil9z.jsp')->status ?? null, 'GET must not be 201');
    }

    public function test_no_500_anywhere(): void
    {
        $probes = [
            ['GET', '/System/configurationFile', '', []],
            ['GET', '/ws/v1/cluster/apps/new-application', '', []],
            ['POST', '/fpui/loginServlet', '', []],
            ['POST', '/.antproxy.php', '', []],
            ['GET', '/webui/logoutconfirm.html', 'logon_hash=1', ['Authorization' => 'deadbeefdeadbeefdead']],
            ['PUT', '/x.jsp', '', []],
            ['GET', '/x.jsp', '', []],
        ];
        foreach ($probes as [$m, $p, $q, $h]) {
            $r = $this->resp($m, $p, $q, $h);
            if ($r !== null) {
                self::assertLessThan(500, $r->status, "{$m} {$p} must never 5xx");
            }
        }
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 300; $s++) {
            foreach ([
                ['GET', '/System/configurationFile', '', []],
                ['GET', '/ws/v1/cluster/apps/new-application', '', []],
                ['GET', '/webui/logoutconfirm.html', 'logon_hash=1', ['Authorization' => '0ff4fbf0ecffa77ce8d3852a29263e263838e9bb']],
            ] as [$m, $p, $q, $h]) {
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $this->body($this->resp($m, $p, $q, $h, null, (string) $s))), "seed {$s} {$p} denylist run");
            }
        }
    }
}
