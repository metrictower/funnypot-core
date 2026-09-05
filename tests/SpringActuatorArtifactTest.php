<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\SpringHprofGenerator;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * The Spring Boot Actuator artifact pair through the full respond() facade: the twelve scanner
 * heapdump paths serve raw HPROF under every style, the corpus logfile bundles serve the Logback log
 * (dressing only the Spring bundle — the iSpy co-tenant on bare /logfile is untouched), and the two
 * artifacts agree on boot date and credentials for one seed, and with the existing /actuator/env
 * surface. Negative controls stay unmatched.
 */
final class SpringActuatorArtifactTest extends TestCase
{
    private const HEAPDUMP_PATHS = [
        '/heapdump',
        '/actuator/heapdump',
        '/bbo-admin/heapdump',
        '/bbo-admin/actuator/heapdump',
        '/bbo-rest/heapdump',
        '/bbo-rest/actuator/heapdump',
        '/bbo-search/heapdump',
        '/bbo-search/actuator/heapdump',
        '/bbo-token/heapdump',
        '/bbo-token/actuator/heapdump',
        '/bbo-vin/heapdump',
        '/bbo-vin/actuator/heapdump',
    ];

    private const HPROF_MAGIC = "JAVA PROFILE 1.0.2\0";

    /** @return array<string,mixed> */
    private static function index(): array
    {
        return require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    }

    private function inverter(string $seed, string $style, string $ceiling = 'high'): Honeypot
    {
        return new Honeypot(new PhpArrayStore(self::index()), new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            $style,
            $ceiling
        ));
    }

    private function serve(Honeypot $inv, string $path): SynthesizedResponse
    {
        $resp = $inv->respond(new RequestContext('GET', $path));
        self::assertNotNull($resp, "{$path} must serve a fake");

        return $resp;
    }

    public function test_every_heapdump_path_serves_raw_hprof_under_every_style(): void
    {
        foreach ([Style::MINIMAL, Style::REALISTIC, Style::TAUNT] as $style) {
            $inv = $this->inverter('fixed', $style);
            foreach (self::HEAPDUMP_PATHS as $path) {
                $where = "{$path} [{$style}]";
                self::assertTrue($inv->detect(new RequestContext('GET', $path))->matched, "{$where} must be detected");
                $resp = $this->serve($inv, $path);
                self::assertSame(200, $resp->status, "{$where} status");
                self::assertSame('application/octet-stream', $resp->headers['Content-Type'] ?? null, "{$where} Content-Type");
                foreach (array_keys($resp->headers) as $name) {
                    self::assertNotSame('content-disposition', strtolower((string) $name), "{$where}: Spring Boot sets no Content-Disposition on heapdump");
                    self::assertNotSame('content-encoding', strtolower((string) $name), "{$where}: raw HPROF, no gzip claim");
                }
                self::assertStringStartsWith(self::HPROF_MAGIC, $resp->body, "{$where} must be raw HPROF (not gzip, not a minimal-synth substitute)");
                self::assertLessThan(4096, strlen($resp->body), "{$where} stays a bounded artifact");
                self::assertStringNotContainsString('{{', $resp->body, "{$where} carries no unrendered directive");
            }
        }
    }

    public function test_heapdump_is_gated_as_high_severity(): void
    {
        // `severity: high` serves under the default ceiling; a stricter ceiling declines it — proof the
        // bundle is not silently `critical` (which the default ceiling would drop) or `info`.
        self::assertNotNull($this->inverter('fixed', Style::REALISTIC, 'high')->respond(new RequestContext('GET', '/actuator/heapdump')));
        self::assertNull($this->inverter('fixed', Style::REALISTIC, 'medium')->respond(new RequestContext('GET', '/actuator/heapdump')));
    }

    public function test_heapdump_negative_controls_stay_unmatched(): void
    {
        // The upstream probe's random negative-control path, sibling spellings and a file extension
        // must not resolve — the twelve exact keys are the whole surface.
        $inv = $this->inverter('fixed', Style::REALISTIC);
        foreach (['/q7z2m9kx/heapdump', '/actuators/heapdump', '/actuator/heapdump.hprof', '/bbo-other/heapdump', '/heapdumps'] as $path) {
            self::assertArrayNotHasKey('GET ' . $path, self::index()['routes'], "{$path} must not be a route key");
            self::assertNull($inv->respond(new RequestContext('GET', $path)), "{$path} must not serve");
        }
    }

    public function test_heapdump_index_shape(): void
    {
        $routes = self::index()['routes'];
        foreach (self::HEAPDUMP_PATHS as $path) {
            $bundles = $routes['GET ' . $path]['b'] ?? null;
            self::assertIsArray($bundles, "GET {$path} must be a route key");
            self::assertCount(1, $bundles, "GET {$path} has exactly the one synthesized bundle");
            $b = $bundles[0];
            self::assertSame('route-actuator-heapdump', $b['pid'] ?? null);
            self::assertSame('high', $b['sev'] ?? null);
            self::assertSame(1, $b['bin'] ?? null, 'bin=1 so ResponseSynthesizer never routes it to minimal synth');
            self::assertSame([], $b['bw'] ?? null);
            self::assertSame(['Content-Type' => ['application/octet-stream']], $b['th'] ?? null);
        }
        $template = self::index()['templates']['route-actuator-heapdump'] ?? null;
        self::assertIsArray($template);
        self::assertSame('high', $template['sev'] ?? null);
    }

    public function test_logfile_paths_serve_the_logback_log_under_realistic_and_taunt(): void
    {
        foreach (['/actuator/logfile', '/actuators/logfile'] as $path) {
            foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
                $where = "{$path} [{$style}]";
                $resp = $this->serve($this->inverter('fixed', $style), $path);
                self::assertSame(200, $resp->status, "{$where} status");
                self::assertSame('text/plain;charset=UTF-8', $resp->headers['Content-Type'] ?? null, "{$where}: Spring's exact media type, no space");
                foreach (['INFO', 'springframework.web.HttpRequestMethodNotSupportedException', 'HikariPool-1', 'jdbc:postgresql://', 'AWS_ACCESS_KEY_ID=AKIA', 'DEBUG'] as $marker) {
                    self::assertStringContainsString($marker, $resp->body, "{$where} must carry '{$marker}'");
                }
                self::assertStringNotContainsString('{{', $resp->body, "{$where} carries no unrendered directive");
                foreach (array_keys($resp->headers) as $name) {
                    self::assertNotSame('accept-ranges', strtolower((string) $name), "{$where}: range support is not claimed");
                }
                // A plain log has no comment syntax: no taunt is authored, so TAUNT is byte-identical.
                self::assertStringNotContainsString('nice try', strtolower($resp->body), "{$where}: no taunt banner in a log file");
            }
            // MINIMAL stays intentionally minimal: the bare bundle words, still text/plain.
            $min = $this->serve($this->inverter('fixed', Style::MINIMAL), $path);
            self::assertSame(200, $min->status);
            self::assertStringContainsString('text/plain', $min->headers['Content-Type'] ?? '');
            self::assertStringContainsString('INFO', $min->body);
        }
    }

    public function test_bare_logfile_keeps_both_bundles_and_the_rule_dresses_only_spring(): void
    {
        $bundles = self::index()['routes']['GET /logfile']['b'] ?? [];
        self::assertCount(2, $bundles, 'bare /logfile keeps its two corpus bundles');
        self::assertSame(['ispy', 'springboot'], array_column($bundles, 'pid'), 'original co-tenant order is preserved');
        self::assertSame(['critical', 'low'], array_column($bundles, 'sev'));
        [$ispy, $spring] = $bundles;
        self::assertSame(['CVE-2022-29775'], $ispy['t']);
        self::assertSame(['springboot-logfile'], $spring['t']);

        // The rule selects by bundle metadata, never by path: Spring is dressed, iSpy is not.
        $set = RouteTemplateSet::fromPackage();
        self::assertSame('route-actuator-logfile', ($set->findRule($spring) ?? [])['id'] ?? null);
        self::assertNotSame('route-actuator-logfile', ($set->findRule($ispy) ?? [])['id'] ?? null, 'the iSpy bundle must never be dressed as a Spring log');

        // Rendered directly, the Spring bundle yields the log with its corpus witnesses intact.
        $emu = new RouteTemplateEmulator($set);
        $content = $emu->render($spring, Style::REALISTIC, 7);
        self::assertNotNull($content);
        self::assertStringContainsString('springframework.web.HttpRequestMethodNotSupportedException', $content->body);
        self::assertStringContainsString('HikariPool-1', $content->body);
        self::assertSame('text/plain;charset=UTF-8', $content->headers['Content-Type'] ?? null);

        // No new bundle or key ownership on the sole-Spring paths.
        foreach (['GET /actuator/logfile', 'GET /actuators/logfile'] as $key) {
            $b = self::index()['routes'][$key]['b'] ?? [];
            self::assertCount(1, $b, "{$key} still has exactly its one corpus bundle");
            self::assertSame('springboot', $b[0]['pid']);
        }
        self::assertArrayNotHasKey('route-actuator-logfile', self::index()['templates'], 'an enrich adds no template entry');
    }

    public function test_heapdump_and_logfile_agree_on_boot_date_and_credentials(): void
    {
        for ($seed = 0; $seed <= 30; $seed++) {
            $inv = $this->inverter((string) $seed, Style::REALISTIC);
            $log = $this->serve($inv, '/actuator/logfile')->body;
            $heap = $this->serve($inv, '/actuator/heapdump')->body;
            $env = $this->serve($inv, '/actuator/env')->body;

            // Boot date: the log's first line names it; the HPROF header stamps that day 08:12:04.112Z.
            self::assertSame(1, preg_match('/^(\d{4}-\d{2}-\d{2})T08:12:04\.112Z  INFO/', $log, $m), "seed {$seed}: log must open with the boot line");
            $date = $m[1];
            self::assertSame(10, preg_match_all('/^(\d{4}-\d{2}-\d{2})T/m', $log, $all), "seed {$seed}: ten dated lines");
            self::assertSame([$date], array_values(array_unique($all[1])), "seed {$seed}: every log line names the one boot day");
            $expectedMs = (int) (new \DateTimeImmutable($date . 'T08:12:04.112Z'))->format('Uv');
            $hi = unpack('N', substr($heap, strlen(self::HPROF_MAGIC) + 4, 4))[1];
            $lo = unpack('N', substr($heap, strlen(self::HPROF_MAGIC) + 8, 4))[1];
            self::assertSame($expectedMs, ($hi << 32) | $lo, "seed {$seed}: HPROF header time must be the log's boot instant");

            // Credentials: the log, the heap and the existing /actuator/env surface disclose one identity.
            self::assertSame(1, preg_match('/ password=(\S+)$/m', $log, $pw), "seed {$seed}: log must leak the datasource password");
            self::assertStringContainsString('spring.datasource.password=' . $pw[1], $heap, "seed {$seed}: heap must plant the same db password");
            self::assertStringContainsString('"spring.datasource.password": {"value": "' . $pw[1] . '"}', $env, "seed {$seed}: /actuator/env must agree on the db password");

            self::assertSame(1, preg_match('/AWS_ACCESS_KEY_ID=(AKIA[A-Z2-7]{16}) AWS_SECRET_ACCESS_KEY=(\S+) AWS_REGION=(\S+)$/m', $log, $aws), "seed {$seed}: log must leak the AWS pair");
            self::assertStringContainsString('AWS_ACCESS_KEY_ID=' . $aws[1], $heap, "seed {$seed}: heap AWS key id");
            self::assertStringContainsString('AWS_SECRET_ACCESS_KEY=' . $aws[2], $heap, "seed {$seed}: heap AWS secret");
            self::assertStringContainsString('AWS_REGION=' . $aws[3], $heap, "seed {$seed}: heap AWS region");

            self::assertSame(1, preg_match('#registration retry for (http://[^:]+:[^@]+@discovery\.internal:8761/eureka/)#', $log, $eureka), "seed {$seed}: log must leak the Eureka URL");
            self::assertStringContainsString('eureka.client.serviceUrl.defaultZone=' . $eureka[1], $heap, "seed {$seed}: heap Eureka URL");

            self::assertSame(1, preg_match('#url=(jdbc:postgresql://[^ ]+) username=(\S+) #', $log, $jdbc), "seed {$seed}: log must leak the JDBC URL");
            self::assertStringContainsString('spring.datasource.url=' . $jdbc[1], $heap, "seed {$seed}: heap JDBC URL");
            self::assertStringContainsString('spring.datasource.username=' . $jdbc[2], $heap, "seed {$seed}: heap db user");
            self::assertStringContainsString('"spring.datasource.url": {"value": "' . $jdbc[1] . '"}', $env, "seed {$seed}: /actuator/env must agree on the JDBC URL");
        }
    }

    public function test_same_seed_renders_are_byte_identical_modulo_request_id(): void
    {
        foreach (['/actuator/heapdump', '/actuator/logfile'] as $path) {
            $inv = $this->inverter('repeat', Style::REALISTIC);
            $a = $this->serve($inv, $path);
            $b = $this->serve($inv, $path);
            self::assertSame($a->body, $b->body, "{$path} body must be deterministic per seed");
            $strip = static function (array $h): array {
                unset($h['X-Request-Id']);
                ksort($h);

                return $h;
            };
            self::assertSame($strip($a->headers), $strip($b->headers), "{$path} headers (bar the fresh request id) must be deterministic");
        }
    }

    public function test_logfile_template_uses_the_generator_date_directive_on_every_line(): void
    {
        // The two artifacts agree on the boot day only because the log repeats the generator's exact
        // keyed pick; a drift in either copy would silently split them.
        $doc = Yaml::parseFile(__DIR__ . '/../templates/route/324-actuator-logfile.yaml');
        $lines = array_values(array_filter(explode("\n", (string) $doc['response']['body']), 'strlen'));
        self::assertGreaterThanOrEqual(10, count($lines));
        foreach ($lines as $line) {
            self::assertStringStartsWith(SpringHprofGenerator::DATE_DIRECTIVE, $line);
        }
        self::assertSame('text/plain;charset=UTF-8', $doc['response']['headers']['Content-Type']);
        self::assertArrayNotHasKey('taunt', $doc);
        self::assertArrayNotHasKey('new_page', $doc, 'logfile is an enrich: it claims no path');
        self::assertSame(['springboot-logfile'], $doc['match']['template_needle']);
    }
}
