<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Response\BundleValidator;
use Funnypot\Core\Response\EmulatedContent;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use PHPUnit\Framework\TestCase;

/**
 * The built-in endpoint fakes are now data (compiled route templates driven by one
 * RouteTemplateEmulator). Each is proven against a REAL compiled bundle: we load the full
 * template index, pick the route/bundle the template claims, assert the route set selects
 * the expected rule, and assert its REALISTIC and TAUNT bodies satisfy that bundle's own
 * matcher constraints (via BundleValidator — the same checks nuclei applies). This is the
 * guarantee that breadth never breaks the scanner contract.
 */
final class EmulatorBreadthTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index = null;

    private function set(): RouteTemplateSet
    {
        return RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');
    }

    /**
     * label => [route key, bundle index within that route, expected route-template id].
     * Every route/bundle here is a real entry in resources/compiled/nuclei-index.full.php.
     *
     * @return array<string, array{0:string,1:int,2:string}>
     */
    public static function targets(): array
    {
        return [
            'wp-config backup (aws + db keys)' => ['GET /wp-config.php-backup', 0, 'route-wp-config'],
            'phpinfo page'                     => ['GET /tool/view/phpinfo.view.php', 0, 'route-phpinfo'],
            'htpasswd'                         => ['GET /.htpasswd', 0, 'route-htpasswd'],
            'apache server-status'             => ['GET /server-status', 0, 'route-apache-server-status'],
            'apache server-info'               => ['GET /server-info', 0, 'route-apache-server-status'],
            'package.json'                     => ['GET /package.json', 0, 'route-package-json'],
            'package-lock.json'                => ['GET /package-lock.json', 0, 'route-package-json'],
            'ssh/pem private key'              => ['GET /cgi-bin/privatekey.pem', 0, 'route-ssh-private-key'],
            'sql dump / db backup'             => ['GET /install/froxlor.sql', 0, 'route-sql-dump'],
            'wp-login (registration open)'     => ['GET /wp-login.php', 1, 'route-wp-login'],
            'weblogic console login'           => ['GET /console/login/LoginForm.jsp', 0, 'route-weblogic'],
            'exchange / owa logon'             => ['GET /owa/auth/logon.aspx', 0, 'route-exchange-owa'],
            'adminer db login'                 => ['GET /adminer.php', 0, 'route-adminer'],
            'joomla administrator'             => ['GET /administrator/', 0, 'route-joomla'],
            'wordpress readme.html'            => ['GET /readme.html', 0, 'route-wp-readme'],
            'citrix gateway logon'             => ['GET /logon/LogonPoint/index.html', 0, 'route-citrix'],
            'apache directory listing'         => ['GET /backup/', 0, 'route-directory-listing'],
            'django admin login'               => ['GET /admin/login/', 1, 'route-django-admin'],

            // Config-file disclosure pack (M8) enrich rules — each dresses a bundle the corpus
            // already routes to. A SPECIFIC needle (not a broad `config`) keeps the enrich from
            // hijacking an unrelated bundle; the satisfaction asserts below are the guard that a
            // dropped bw/nf/hw would silently fall back to minimal synth.
            'application.yml enrich'           => ['GET /application.yml', 0, 'route-application-yml'],
            'settings.json enrich'             => ['GET /settings.json', 0, 'route-settings-json'],
            'web.config enrich'                => ['GET /web.config', 0, 'route-web-config'],
            'config.js firebase enrich'        => ['GET /config.js', 0, 'route-config-js-firebase'],

            // Log-file disclosure pack enrich rules — each dresses a log bundle the corpus already
            // routes to. A full-upstream-id needle keeps the enrich from hijacking an unrelated
            // bundle; the satisfaction asserts guard against a dropped bw/hw silently falling back to
            // minimal synth. /log/access.log carries BOTH the iceflow and the generic access-log-file
            // needles; the dedicated iceflow enrich (priority 290) is checked before route-access-log
            // (296), so it wins there and serves the coherent ICEFLOW VPN body (asserted below).
            'npm-debug.log enrich'             => ['GET /npm-debug.log', 0, 'route-npm-debug-log'],
            'laravel.log enrich'               => ['GET /storage/logs/laravel.log', 0, 'route-laravel-log-file'],
            'firebase-debug.log enrich'        => ['GET /firebase-debug.log', 0, 'route-firebase-debug-log'],
            'magento debug.log enrich'         => ['GET /var/log/debug.log', 0, 'route-magento-debug-log'],
            'rails development.log enrich'     => ['GET /development.log', 0, 'route-rails-development-log'],
            'rails production.log enrich'      => ['GET /production.log', 0, 'route-rails-production-log'],
            'access.log enrich'                => ['GET /access.log', 0, 'route-access-log'],
            'iceflow /log/access.log enrich'   => ['GET /log/access.log', 0, 'route-iceflow-vpn-log'],
            'iceflow /log/vpn.log enrich'      => ['GET /log/vpn.log', 0, 'route-iceflow-vpn-log'],

            // Framework debug-page disclosure pack enrich rules — each dresses a corpus-routed
            // detection endpoint (Ignition / Symfony profiler / Werkzeug console / Spring actuator /
            // Telescope) with a specific full-upstream-id needle. The satisfaction asserts guard
            // against a dropped bw/hw silently falling back to minimal synth. /console carries THREE
            // co-bundles; the werkzeug enrich targets bundle index 2 (websphere=0, selenium=1). The
            // Ignition logs page is omitted here: its `{"log_messages"` body word pins the opening
            // brace, so it carries no JSON `_comment` taunt and is covered by NewPageRoutingTest.
            'ignition health-check enrich'     => ['GET /_ignition/health-check', 0, 'route-ignition-health-check'],
            'symfony profiler enrich'          => ['GET /_profiler/empty/search/results', 0, 'route-symfony-profiler'],
            'werkzeug console enrich'          => ['GET /console', 2, 'route-werkzeug-console'],
            'laravel telescope enrich'         => ['GET /telescope/requests', 0, 'route-telescope'],
            'actuator /env enrich'             => ['GET /actuator/env', 0, 'route-actuator-env'],
            'actuator /health enrich'          => ['GET /actuator/health', 0, 'route-actuator-health'],
            'actuator /mappings enrich'        => ['GET /actuator/mappings', 0, 'route-actuator-mappings'],
            'actuator /info enrich'            => ['GET /actuator/info', 0, 'route-actuator-info'],
            'actuator /beans enrich'           => ['GET /actuator/beans', 0, 'route-actuator-beans'],
            'actuator /loggers enrich'         => ['GET /actuator/loggers', 0, 'route-actuator-loggers'],
            'actuator /threaddump enrich'      => ['GET /actuator/threaddump', 0, 'route-actuator-threaddump'],
            'actuator /configprops enrich'     => ['GET /actuator/configprops', 0, 'route-actuator-configprops'],

            // IoT / appliance HTTP disclosure pack — each dresses a device-info/config bundle the
            // corpus already routes to (a fake camera / router / NAS / printer / DVR endpoint a
            // scanner hammers). Every needle is a full upstream CVE id / slug that resolves to
            // EXACTLY ONE bundle (findRule is global; a generic device pid — hikvision/router/hp/… —
            // would shadow dozens of routes). The satisfaction asserts guard against a dropped
            // bw/hw/CT silently falling back to minimal synth. Several routes are multi-bundle; the
            // enrich targets bundle 0 (its full-id needle can't hijack a sibling). Content-Type is
            // exact for the typed-CT bundles (Hikvision application/xml, D-Link getcfg text/xml,
            // Dahua application/octet-stream), asserted separately in test_iot_pack_content_types_are_exact.
            'hikvision deviceInfo enrich'      => ['GET /system/deviceInfo', 0, 'route-hikvision-deviceinfo'],
            'hikvision users enrich'           => ['GET /Security/users', 0, 'route-hikvision-users'],
            'netgear currentsetting enrich'    => ['GET /currentsetting.htm', 0, 'route-netgear-currentsetting'],
            'synology dsm enrich'              => ['GET /webapi/entry.cgi', 0, 'route-synology-dsm'],
            'avtech machine.cgi enrich'        => ['GET /cgi-bin/nobody/Machine.cgi', 0, 'route-avtech-machine'],
            'tbk dvr device.rsp enrich'        => ['GET /device.rsp', 0, 'route-tbk-dvr-devicersp'],
            'huawei deviceinfo enrich'         => ['GET /api/system/deviceinfo', 0, 'route-huawei-deviceinfo'],
            'dlink info.cgi enrich'            => ['GET /cgi-bin/info.cgi', 0, 'route-dlink-info-cgi'],
            'dahua Sha1Account1 enrich'        => ['GET /current_config/Sha1Account1', 0, 'route-dahua-sha1account'],
            'apollo device/config enrich'      => ['GET /device/config', 0, 'route-apollo-device-config'],
            'dahua passwd enrich'              => ['GET /current_config/passwd', 0, 'route-dahua-passwd'],
            'qnap qts panel enrich'            => ['GET /cgi-bin/', 0, 'route-qnap-qts'],
            'hp device info enrich'            => ['GET /hp/device/DeviceInformation/View', 0, 'route-hp-device-info'],
            'openwrt luci enrich'              => ['GET /cgi-bin/luci', 0, 'route-openwrt-luci'],
            'dlink getcfg enrich'              => ['GET /getcfg.php', 0, 'route-dlink-getcfg'],
            'wavlink ExportAllSettings enrich' => ['GET /cgi-bin/ExportAllSettings.sh', 0, 'route-wavlink-exportsettings'],
            'epson PRTINFO enrich'             => ['GET /PRESENTATION/HTML/TOP/PRTINFO.HTML', 0, 'route-epson-prtinfo'],
            'hp color laserjet enrich'         => ['GET /hp/device/this.LCDispatcher', 0, 'route-hp-color-laserjet'],

            // Management / admin-panel disclosure pack — each dresses a control-panel bundle the corpus
            // already routes to (a fake Webmin / phpPgAdmin / Kibana / Jenkins / Grafana panel a scanner
            // hammers). Every needle is a full upstream slug that resolves to EXACTLY ONE bundle
            // (findRule is global; a generic pid would shadow other routes). All five are rx=0 and serve
            // at the default (high) ceiling. Content-Type is exact for the JSON bundle (Grafana settings
            // application/json), asserted separately in test_panel_pack_content_types_are_exact.
            'webmin panel enrich'              => ['GET /webmin/', 0, 'route-webmin'],
            'phppgadmin panel enrich'          => ['GET /phppgadmin/', 0, 'route-phppgadmin'],
            'kibana panel enrich'              => ['GET /app/kibana', 0, 'route-kibana'],
            // The Kibana rule also folds the bare /kibana(/) mounts as new-page aliases (pid =
            // route-kibana); the alias bundle must satisfy through the same authored shell.
            'kibana bare alias (new-page)'     => ['GET /kibana', 0, 'route-kibana'],
            'jenkins panel enrich'             => ['GET /jenkins/', 0, 'route-jenkins'],
            'grafana settings enrich'          => ['GET /api/frontend/settings', 0, 'route-grafana-settings'],
        ];
    }

    /**
     * The IoT pack's needles are full upstream CVE ids / slugs, but findRule is GLOBAL (a needle that
     * is a substring of ANY t-id in ANY bundle shadows that route). Lock every needle to EXACTLY ONE
     * bundle id across the whole compiled index, and forbid any IoT needle from being a bare generic
     * device pid (hikvision/router/hp/camera/…) that substrings dozens of routes — the M8/API-recon
     * lesson made a CI guard.
     */
    public function test_iot_pack_needles_are_unique_and_carry_no_generic_pid(): void
    {
        $routes = self::index()['routes'] ?? [];
        $distinctIds = static function (string $needle) use ($routes): array {
            $ids = [];
            foreach ($routes as $entry) {
                foreach ((array) ($entry['b'] ?? []) as $b) {
                    if ((string) ($b['pid'] ?? '') === $needle) {
                        $ids[$needle . ' (pid)'] = true;
                    }
                    foreach (array_map('strval', (array) ($b['t'] ?? [])) as $id) {
                        if (strpos($id, $needle) !== false) {
                            $ids[$id] = true;
                        }
                    }
                }
            }

            return array_keys($ids);
        };

        $needles = [
            'CVE-2017-7921', 'hikvision-cam-info-exposure', 'CVE-2024-30569', 'synology-dsm-system-info',
            'avtech-dvr-exposure', 'CVE-2018-9995', 'huawei-router-auth-bypass', 'CVE-2024-3274',
            'CVE-2017-8229', 'CVE-2024-25735', 'CVE-2017-7925', 'qnap-qts-panel', 'hp-device-info-detect',
            'openwrt-luci-panel', 'CVE-2025-14528', 'CVE-2020-12127', 'epson-wf-series', 'hp-color-laserjet-detect',
        ];
        foreach ($needles as $needle) {
            self::assertCount(1, $distinctIds($needle), "IoT needle '{$needle}' must resolve to exactly one bundle id (else findRule shadows another route)");
        }

        // A generic device pid substrings dozens of routes; no IoT enrich may use one as a needle.
        $generic = ['hp', 'camera', 'printer', 'hikvision', 'router', 'luci', 'laserjet', 'nas', 'firmware', 'cgi', 'dvr', 'qts', 'device', 'nvr'];
        foreach ((require __DIR__ . '/../resources/compiled/funnypot-routes.php') as $rule) {
            if (strpos((string) $rule['id'], 'route-') !== 0) {
                continue;
            }
            foreach ((array) ($rule['match']['template_needle'] ?? []) as $n) {
                self::assertNotContains((string) $n, $generic, "route template {$rule['id']} must not use a generic device pid needle '{$n}'");
            }
        }
    }

    /**
     * Content-Type is a fingerprint tell AND a matcher gate: a bundle carrying a typed Content-Type
     * check (Hikvision application/xml, D-Link getcfg text/xml, Dahua application/octet-stream) drops
     * to minimal synth if the enrich serves the wrong media type — application/xml does NOT satisfy a
     * text/xml check and vice-versa. Assert every IoT enrich emits its EXACT required Content-Type.
     */
    public function test_iot_pack_content_types_are_exact(): void
    {
        $expected = [
            'GET /system/deviceInfo'                  => 'application/xml',
            'GET /Security/users'                     => 'application/xml',
            'GET /currentsetting.htm'                 => 'text/html; charset=UTF-8',
            'GET /webapi/entry.cgi'                   => 'application/json',
            'GET /cgi-bin/nobody/Machine.cgi'         => 'text/plain; charset=utf-8',
            'GET /device.rsp'                         => 'application/json',
            'GET /api/system/deviceinfo'              => 'text/xml; charset=utf-8',
            'GET /cgi-bin/info.cgi'                   => 'text/plain; charset=utf-8',
            'GET /current_config/Sha1Account1'        => 'application/octet-stream',
            'GET /device/config'                      => 'application/json',
            'GET /current_config/passwd'              => 'text/plain; charset=utf-8',
            'GET /cgi-bin/'                           => 'text/html; charset=utf-8',
            'GET /hp/device/DeviceInformation/View'   => 'text/html; charset=utf-8',
            'GET /cgi-bin/luci'                       => 'text/html; charset=utf-8',
            'GET /getcfg.php'                         => 'text/xml',
            'GET /cgi-bin/ExportAllSettings.sh'       => 'text/plain; charset=utf-8',
            'GET /PRESENTATION/HTML/TOP/PRTINFO.HTML' => 'text/html; charset=utf-8',
            'GET /hp/device/this.LCDispatcher'        => 'text/html; charset=utf-8',
        ];
        $emulator = new RouteTemplateEmulator($this->set());
        foreach ($expected as $route => $ct) {
            $bundle = $this->bundle($route, 0);
            $content = $emulator->render($bundle, Style::REALISTIC, 7);
            self::assertNotNull($content, "{$route} must render");
            self::assertSame($ct, $content->headers['Content-Type'] ?? null, "{$route} Content-Type must be exact ({$ct})");
            // Any typed Content-Type check the bundle carries must be a substring of the emitted value.
            foreach (array_map('strval', (array) ($bundle['th']['Content-Type'] ?? [])) as $sub) {
                self::assertStringContainsString($sub, (string) ($content->headers['Content-Type'] ?? ''), "{$route} typed Content-Type must contain '{$sub}'");
            }
        }
    }

    /**
     * The XML/JSON device pages must stay well-formed for BOTH the realistic body and the taunt body
     * (a block XML comment / a JSON `_comment` field) across the persona pick space — a dropped bw
     * appended as a bare line, or a mis-escaped value, would break the parser and betray the fake.
     */
    public function test_iot_xml_and_json_bodies_are_valid(): void
    {
        $xml = [
            'GET /system/deviceInfo', 'GET /Security/users', 'GET /api/system/deviceinfo', 'GET /getcfg.php',
        ];
        $json = [
            'GET /webapi/entry.cgi', 'GET /device.rsp', 'GET /device/config',
        ];
        $emulator = new RouteTemplateEmulator($this->set());
        foreach (self::seeds() as $seed) {
            foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
                foreach ($xml as $route) {
                    $content = $emulator->render($this->bundle($route, 0), $style, $seed);
                    self::assertNotNull($content, "{$route} must render (seed {$seed}, {$style})");
                    $prev = libxml_use_internal_errors(true);
                    $doc = new \DOMDocument();
                    $ok = $doc->loadXML($content->body);
                    libxml_clear_errors();
                    libxml_use_internal_errors($prev);
                    self::assertTrue($ok, "{$route} must be well-formed XML (seed {$seed}, {$style})");
                }
                foreach ($json as $route) {
                    $content = $emulator->render($this->bundle($route, 0), $style, $seed);
                    self::assertNotNull($content, "{$route} must render (seed {$seed}, {$style})");
                    self::assertIsArray(json_decode($content->body, true), "{$route} must be valid JSON (seed {$seed}, {$style}): " . $content->body);
                }
            }
        }
    }

    /**
     * The number-safety gate (the bare \b9\d{5}\b CRS-rule-id run, plus every literal signature) must
     * hold for the SERVED device bodies across a wide persona sweep, in both styles — a rendered MAC /
     * serial / firmware / uptime island that trips it would let a scanner classify the reply as canned.
     * Rendered at the emulator so the sweep is exact to the IoT bodies (ceiling/bundle-selection blind).
     */
    public function test_iot_pack_bodies_carry_no_denied_fingerprint_token(): void
    {
        $guard = \Funnypot\Core\Compiler\Crs\FingerprintGuard::fromPackage();
        $emulator = new RouteTemplateEmulator($this->set());
        $routes = [];
        foreach (self::targets() as $t) {
            if (strpos($t[2], 'route-hikvision') === 0 || strpos($t[2], 'route-netgear') === 0
                || strpos($t[2], 'route-synology') === 0 || strpos($t[2], 'route-avtech') === 0
                || strpos($t[2], 'route-tbk') === 0 || strpos($t[2], 'route-huawei') === 0
                || strpos($t[2], 'route-dlink') === 0 || strpos($t[2], 'route-dahua') === 0
                || strpos($t[2], 'route-apollo') === 0 || strpos($t[2], 'route-qnap') === 0
                || strpos($t[2], 'route-hp-') === 0 || strpos($t[2], 'route-openwrt') === 0
                || strpos($t[2], 'route-wavlink') === 0 || strpos($t[2], 'route-epson') === 0) {
                $routes[$t[0]] = $t[1];
            }
        }
        self::assertCount(18, $routes, 'the IoT denied-token sweep must cover all 18 targets');
        // The synthesizer renders at crc32(personaSeedString), so sweep THAT value space (raw 0..N
        // would only sample small ints and miss a value-dependent leak — the bounded-6 hex island the
        // end-to-end sweep caught). A 6-digit-run hazard is value-dependent, so a wide sample matters.
        for ($i = 0; $i <= 2000; $i++) {
            $seed = crc32((string) $i);
            foreach ($routes as $route => $bi) {
                foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
                    $content = $emulator->render($this->bundle($route, $bi), $style, $seed);
                    self::assertNotNull($content, "{$route} must render (seed#{$i})");
                    $hits = $guard->scan($content->body);
                    self::assertSame([], $hits, "{$route} seed#{$i} (crc32={$seed}) [{$style}] leaks a denied token (" . implode(',', $hits) . "): " . $content->body);
                }
            }
        }
    }

    /**
     * Device identity is coherent WITHIN a vendor: a fake.NAME reused across two surfaces of one
     * device renders byte-identical (same seed ⇒ same value, path-independent), so an attacker who
     * reads both pages sees one consistent device. The Dahua admin password digest appears on BOTH
     * /current_config/Sha1Account1 and /current_config/passwd; the Hikvision MAC always carries the
     * real vendor OUI constant.
     */
    public function test_iot_device_identity_is_coherent_across_a_vendors_surfaces(): void
    {
        $emulator = new RouteTemplateEmulator($this->set());
        foreach ([0, 1, 7, 42, 777, 123456] as $seed) {
            $sha1 = $emulator->render($this->bundle('GET /current_config/Sha1Account1', 0), Style::REALISTIC, $seed);
            $passwd = $emulator->render($this->bundle('GET /current_config/passwd', 0), Style::REALISTIC, $seed);
            self::assertNotNull($sha1);
            self::assertNotNull($passwd);
            self::assertSame(1, preg_match('/table\.Account1\.Password=([0-9a-f]{40})/', $sha1->body, $a), "Sha1Account1 must disclose the admin password digest (seed {$seed})");
            self::assertSame(1, preg_match('/^1:admin:([0-9a-f]{40}):/m', $passwd->body, $b), "passwd must disclose the admin password digest (seed {$seed})");
            self::assertSame($a[1], $b[1], "the Dahua admin password digest must be byte-identical across its two surfaces (seed {$seed})");
        }

        // The Hikvision MAC always carries the real 44:19:b6 OUI, whatever the seed.
        for ($seed = 0; $seed <= 30; $seed++) {
            $dev = $emulator->render($this->bundle('GET /system/deviceInfo', 0), Style::REALISTIC, $seed);
            self::assertNotNull($dev);
            self::assertSame(1, preg_match('/<macAddress>44:19:b6:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}<\/macAddress>/', $dev->body), "Hikvision MAC must carry the 44:19:b6 vendor OUI (seed {$seed})");
        }

        // Synology DS220+ is an x86 "plus" model, so it must report the real Intel Celeron J4025 — never
        // the Realtek RTD1296 ARM SoC, which ships only on the value/ARM DiskStations. This model↔CPU
        // pairing is exactly what a spec-sheet cross-check verifies, so lock it across the seed spread.
        for ($seed = 0; $seed <= 30; $seed++) {
            $syno = $emulator->render($this->bundle('GET /webapi/entry.cgi', 0), Style::REALISTIC, $seed);
            self::assertNotNull($syno);
            $info = json_decode($syno->body, true);
            self::assertIsArray($info, "Synology body must be valid JSON (seed {$seed})");
            $sys = $info['data']['result'][0]['data'] ?? [];
            self::assertSame('DS220+', $sys['model'] ?? null, "Synology model must be DS220+ (seed {$seed})");
            self::assertSame('J4025', $sys['cpu_series'] ?? null, "DS220+ must report the Intel Celeron J4025 CPU (seed {$seed})");
            self::assertSame('INTEL', $sys['cpu_vendor'] ?? null, "DS220+ CPU vendor must be Intel (seed {$seed})");
            self::assertStringNotContainsString('Realtek', $syno->body, "DS220+ must never report a Realtek ARM CPU (seed {$seed})");
        }

        // Wavlink WN530H4 (CVE-2020-12127): all three identity signals must name one maker — model
        // WN530H4, a WAVLINK-prefixed SSID, and a WAN MAC in Wavlink's real IEEE OUI f4:0f:9b — with no
        // trace of the earlier Tenda OUI (c8:3a:35) or Motorola SSID. A spec-sheet + OUI lookup catches
        // a three-vendor mismatch, so lock the coherence across the seed spread.
        for ($seed = 0; $seed <= 30; $seed++) {
            $wl = $emulator->render($this->bundle('GET /cgi-bin/ExportAllSettings.sh', 0), Style::REALISTIC, $seed);
            self::assertNotNull($wl);
            self::assertStringContainsString('Model=WN530H4', $wl->body, "Wavlink model must be WN530H4 (seed {$seed})");
            self::assertSame(1, preg_match('/^SSID=WAVLINK-/m', $wl->body), "Wavlink SSID must carry the WAVLINK- prefix (seed {$seed})");
            self::assertSame(1, preg_match('/^WANMAC=f4:0f:9b:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/m', $wl->body), "Wavlink WAN MAC must carry the f4:0f:9b vendor OUI (seed {$seed})");
            self::assertStringNotContainsString('c8:3a:35', $wl->body, "Wavlink dump must not carry the Tenda OUI (seed {$seed})");
            self::assertStringNotContainsString('MOTO_', $wl->body, "Wavlink dump must not carry a Motorola SSID (seed {$seed})");
        }
    }

    /**
     * The disclosure pack's needles must each resolve to EXACTLY ONE bundle id, or the global
     * findRule would shadow an unrelated route. This is the guard behind the deliberate `/actuator`
     * index skip: `springboot-actuator` substrings `springboot-actuators-jolokia-xxe`, so it hits
     * two ids and is intentionally NOT used as a needle (the bare /actuator index is left to minimal
     * synth). Every leaf needle we DO use is asserted unique across the whole compiled index.
     */
    public function test_debug_pack_needles_are_unique_and_actuator_index_is_skipped(): void
    {
        $routes = self::index()['routes'] ?? [];
        $distinctIds = static function (string $needle) use ($routes): array {
            $ids = [];
            foreach ($routes as $entry) {
                foreach ((array) ($entry['b'] ?? []) as $b) {
                    if ((string) ($b['pid'] ?? '') === $needle) {
                        $ids[$needle . ' (pid)'] = true;
                    }
                    foreach (array_map('strval', (array) ($b['t'] ?? [])) as $id) {
                        if (strpos($id, $needle) !== false) {
                            $ids[$id] = true;
                        }
                    }
                }
            }

            return array_keys($ids);
        };

        $needles = [
            'laravel-debug-enabled', 'laravel-ignition-log-viewer', 'symfony-profiler',
            'werkzeug-debugger-detect', 'laravel-telescope', 'springboot-env', 'springboot-health',
            'springboot-mappings', 'springboot-info', 'springboot-beans', 'springboot-loggers',
            'springboot-threaddump', 'springboot-configprops',
        ];
        foreach ($needles as $needle) {
            self::assertCount(1, $distinctIds($needle), "needle '{$needle}' must resolve to exactly one bundle id (else findRule shadows another route)");
        }

        // The collision the pack avoids: `springboot-actuator` is a substring of the jolokia-xxe id,
        // so it hits >1 id and must NOT be used as an enrich needle. No shipped route template does.
        self::assertGreaterThan(1, count($distinctIds('springboot-actuator')), 'springboot-actuator must hit >1 id (this is why /actuator index is not enriched)');
        $set = $this->set();
        foreach ((require __DIR__ . '/../resources/compiled/funnypot-routes.php') as $rule) {
            foreach ((array) ($rule['match']['template_needle'] ?? []) as $n) {
                self::assertNotSame('springboot-actuator', (string) $n, "route template {$rule['id']} must not use the colliding springboot-actuator needle");
            }
        }
    }

    /**
     * The API-recon pack's enrich needles are bare, generic substrings (e.g. `openapi`), so a corpus
     * refresh that introduced a colliding t-id would silently make findRule serve the wrong enrich on
     * an unrelated route. Lock each to EXACTLY ONE bundle id across the whole compiled index, so such a
     * collision fails CI before a rules release is signed.
     */
    public function test_apirecon_pack_needles_are_unique(): void
    {
        $routes = self::index()['routes'] ?? [];
        $distinctIds = static function (string $needle) use ($routes): array {
            $ids = [];
            foreach ($routes as $entry) {
                foreach ((array) ($entry['b'] ?? []) as $b) {
                    if ((string) ($b['pid'] ?? '') === $needle) {
                        $ids[$needle . ' (pid)'] = true;
                    }
                    foreach (array_map('strval', (array) ($b['t'] ?? [])) as $id) {
                        if (strpos($id, $needle) !== false) {
                            $ids[$id] = true;
                        }
                    }
                }
            }

            return array_keys($ids);
        };

        $needles = ['openapi', 'fastapi-docs', 'redoc-api-docs', 'security-txt', 'openai-plugin', 'CVE-2019-9880'];
        foreach ($needles as $needle) {
            self::assertCount(1, $distinctIds($needle), "API-recon needle '{$needle}' must resolve to exactly one bundle id (else findRule shadows another route)");
        }
    }

    /**
     * The management/admin-panel pack's enrich needles are full upstream slugs, but findRule is GLOBAL
     * (a needle that is a substring of ANY t-id in ANY bundle shadows that route). Lock each to EXACTLY
     * ONE bundle id across the whole compiled index — /app/kibana carries two co-ids and the enrich
     * deliberately keys on the tighter `exposed-kibana` — so a corpus refresh that introduced a
     * colliding t-id fails CI before a rules release is signed. The Kibana rule's bare /kibana(/)
     * aliases are keyed by its own pid (`route-kibana`), which neither equals nor substrings
     * `exposed-kibana`, so they never inflate this count.
     */
    public function test_panel_pack_needles_are_unique(): void
    {
        $routes = self::index()['routes'] ?? [];
        $distinctIds = static function (string $needle) use ($routes): array {
            $ids = [];
            foreach ($routes as $entry) {
                foreach ((array) ($entry['b'] ?? []) as $b) {
                    if ((string) ($b['pid'] ?? '') === $needle) {
                        $ids[$needle . ' (pid)'] = true;
                    }
                    foreach (array_map('strval', (array) ($b['t'] ?? [])) as $id) {
                        if (strpos($id, $needle) !== false) {
                            $ids[$id] = true;
                        }
                    }
                }
            }

            return array_keys($ids);
        };

        $needles = ['webmin-panel', 'phppgadmin-panel', 'exposed-kibana', 'unauthenticated-jenkins', 'grafana-unauth-access'];
        foreach ($needles as $needle) {
            self::assertCount(1, $distinctIds($needle), "panel needle '{$needle}' must resolve to exactly one bundle id (else findRule shadows another route)");
        }
    }

    /**
     * Content-Type is a fingerprint tell AND a matcher gate: a login/dashboard page served as JSON, or
     * a JSON settings endpoint served as HTML, drops to minimal synth and is itself a tell. Assert each
     * panel enrich emits its EXACT Content-Type — the four HTML panels vs the Grafana settings JSON.
     */
    public function test_panel_pack_content_types_are_exact(): void
    {
        $expected = [
            'GET /webmin/'               => 'text/html; charset=utf-8',
            'GET /phppgadmin/'           => 'text/html; charset=utf-8',
            'GET /app/kibana'            => 'text/html; charset=utf-8',
            'GET /kibana'                => 'text/html; charset=utf-8',
            'GET /kibana/'               => 'text/html; charset=utf-8',
            'GET /jenkins/'              => 'text/html; charset=utf-8',
            'GET /api/frontend/settings' => 'application/json',
        ];
        $emulator = new RouteTemplateEmulator($this->set());
        foreach ($expected as $route => $ct) {
            $content = $emulator->render($this->bundle($route, 0), Style::REALISTIC, 7);
            self::assertNotNull($content, "{$route} must render");
            self::assertSame($ct, $content->headers['Content-Type'] ?? null, "{$route} Content-Type must be exact ({$ct})");
        }
    }

    /**
     * The Grafana /api/frontend/settings enrich is served application/json, so it must stay well-formed
     * JSON for BOTH the realistic body and the `_comment` taunt across the persona pick space — a
     * dropped body word appended as a bare line, or a mis-escaped value, would break the parser and
     * betray the fake.
     */
    public function test_grafana_settings_json_is_valid(): void
    {
        $emulator = new RouteTemplateEmulator($this->set());
        $bundle = $this->bundle('GET /api/frontend/settings', 0);
        foreach (self::seeds() as $seed) {
            foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
                $content = $emulator->render($bundle, $style, $seed);
                self::assertNotNull($content, "grafana settings must render (seed {$seed}, {$style})");
                self::assertSame('application/json', $content->headers['Content-Type'] ?? null, "grafana settings Content-Type (seed {$seed}, {$style})");
                self::assertIsArray(json_decode($content->body, true), "grafana settings must be valid JSON (seed {$seed}, {$style}): " . $content->body);
            }
        }
    }

    /**
     * The Jenkins panel enrich carries the exact header set a scanner keys on to confirm Jenkins and
     * lift its version — `X-Jenkins` (the version), `X-Hudson` (the legacy constant), and a nosniff
     * guard. A dropped X-Jenkins header would leave the fake indistinguishable from a generic HTML page.
     */
    public function test_jenkins_enrich_carries_the_version_headers(): void
    {
        $emulator = new RouteTemplateEmulator($this->set());
        for ($seed = 0; $seed <= 30; $seed++) {
            $content = $emulator->render($this->bundle('GET /jenkins/', 0), Style::REALISTIC, $seed);
            self::assertNotNull($content, "jenkins panel must render (seed {$seed})");
            self::assertSame('2.426.3', $content->headers['X-Jenkins'] ?? null, "jenkins panel must carry X-Jenkins (seed {$seed})");
            self::assertSame('1.395', $content->headers['X-Hudson'] ?? null, "jenkins panel must carry X-Hudson (seed {$seed})");
            self::assertSame('nosniff', $content->headers['X-Content-Type-Options'] ?? null, "jenkins panel must carry the nosniff guard (seed {$seed})");
        }
    }

    /**
     * @dataProvider targets
     */
    public function test_route_set_selects_the_expected_template(string $route, int $i, string $id): void
    {
        $rule = $this->set()->findRule($this->bundle($route, $i));

        self::assertNotNull($rule, "{$route} #{$i} must select a route template");
        self::assertSame($id, $rule['id'], "{$route} #{$i} must be served by {$id}");
    }

    /**
     * A spread of persona seeds, so satisfaction is proven across the pick space — not at one
     * lucky literal. A dictionary-entry or alphabet regression that breaks only some seeds (e.g. a
     * value that displaces a required body word) surfaces here where a single fixed seed would miss it.
     *
     * @return int[]
     */
    private static function seeds(): array
    {
        $seeds = [0, 1, 2, 3, 7, 42, 777, 4242, 99999, 123456, 2020202];
        for ($s = 10; $s <= 60; $s += 3) {
            $seeds[] = $s;
        }

        return $seeds;
    }

    /**
     * @dataProvider targets
     */
    public function test_realistic_body_satisfies_the_real_bundle(string $route, int $i, string $id): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = new RouteTemplateEmulator($this->set());

        foreach (self::seeds() as $seed) {
            $content = $emulator->render($bundle, Style::REALISTIC, $seed);
            self::assertNotNull($content, "{$route} realistic render must not decline its own bundle (seed {$seed})");
            self::assertTrue(
                BundleValidator::satisfies($content->body, $this->headers($bundle, $content), $bundle),
                "{$route} realistic body must satisfy the compiled matcher (seed {$seed})"
            );
        }
    }

    /**
     * @dataProvider targets
     */
    public function test_taunt_body_satisfies_and_carries_the_marker(string $route, int $i, string $id): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = new RouteTemplateEmulator($this->set());

        foreach (self::seeds() as $seed) {
            $content = $emulator->render($bundle, Style::TAUNT, $seed);
            self::assertNotNull($content, "{$route} taunt render must not decline its own bundle (seed {$seed})");
            self::assertTrue(
                BundleValidator::satisfies($content->body, $this->headers($bundle, $content), $bundle),
                "{$route} taunt body must still satisfy the compiled matcher (seed {$seed})"
            );
            self::assertStringContainsStringIgnoringCase('nice try', $content->body, "{$route} taunt must carry the marker (seed {$seed})");
        }
    }

    /**
     * @dataProvider targets
     */
    public function test_output_is_byte_identical_per_seed(string $route, int $i, string $id): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = new RouteTemplateEmulator($this->set());

        $a = $emulator->render($bundle, Style::REALISTIC, 777);
        $b = $emulator->render($bundle, Style::REALISTIC, 777);
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, "{$route} must render identically for a fixed seed");
    }

    public function test_config_js_bundles_resolve_to_coherent_rules(): void
    {
        // The /config.js corpus route carries TWO bundles: a Firebase config (b0) and a React
        // runtime-env (b1). A broad `env-` needle on route-dotenv used to substring-hijack b1
        // (reactapp-env-js) and dress the JS endpoint as a Laravel .env. Assert each bundle now
        // resolves to its own coherent rule — b1 must be route-react-runtime-env, never route-dotenv.
        $set = $this->set();
        $r0 = $set->findRule($this->bundle('GET /config.js', 0));
        $r1 = $set->findRule($this->bundle('GET /config.js', 1));
        self::assertNotNull($r0, 'config.js firebase bundle must select a rule');
        self::assertNotNull($r1, 'config.js react runtime-env bundle must select a rule');
        self::assertSame('route-config-js-firebase', $r0['id']);
        self::assertSame('route-react-runtime-env', $r1['id'], 'react bundle must NOT resolve to route-dotenv');
        // Neither rule may dress this .js endpoint as a Laravel .env (the hijack tell).
        self::assertStringNotContainsString('APP_DEBUG=', (string) $r0['body']);
        self::assertStringNotContainsString('APP_DEBUG=', (string) $r1['body']);
    }

    /**
     * @return array<string,mixed> a single compiled bundle
     */
    private function bundle(string $route, int $i): array
    {
        $routes = self::index()['routes'] ?? [];
        self::assertArrayHasKey($route, $routes, "route {$route} is not in the compiled index");
        self::assertArrayHasKey($i, $routes[$route]['b'] ?? [], "bundle #{$i} is not present at {$route}");

        return $routes[$route]['b'][$i];
    }

    /**
     * Header set the way the synthesizer assembles it: the bundle's base headers with the
     * emulator's overrides on top. BundleValidator builds the header block from this.
     *
     * @param array<string,mixed> $bundle
     * @return array<string,string>
     */
    private function headers(array $bundle, EmulatedContent $content): array
    {
        $headers = [];
        foreach ((array) ($bundle['h'] ?? []) as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }
        foreach ($content->headers as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }

        return $headers;
    }

    /**
     * @return array<string,mixed>
     */
    private static function index(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }
}
