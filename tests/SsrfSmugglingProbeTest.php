<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\SsrfSmugglingProbe;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0472 (detection slice): the SSRF protocol-smuggling probe signal fold. A smuggled stream (a raw
 * internal-service payload wrapped in gopher://dict://tftp://ldap://) folds a telemetry Detection tagged
 * `ssrf.smuggling.<family>` without changing a served byte (signal-only, like WaymapProbe/OastProbe).
 * The deceptive responder + structured LHOST/LPORT evidence are deferred to the app tier.
 */
final class SsrfSmugglingProbeTest extends TestCase
{
    private function engine(): Honeypot
    {
        return new Honeypot(
            new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php'),
            new Config('detect', null, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0, false)
        );
    }

    private function probe(string $query): RequestContext
    {
        return new RequestContext('GET', '/fetch', $query, [], null, 'x.test');
    }

    /** @return array<string,array{0:string,1:string,2:string}> label => [query, family, severity] */
    public function smugglingPayloads(): array
    {
        return [
            // gopher Redis cron/rdb webshell drop (the canonical SSRF-to-RCE): RESP framing over %0D%0A.
            'redis-cron' => [
                'url=' . rawurlencode('gopher://127.0.0.1:6379/_*1%0D%0A$8%0D%0Aflushall%0D%0A*4%0D%0A$6%0D%0Aconfig%0D%0A$3%0D%0Aset%0D%0A$3%0D%0Adir%0D%0A'),
                SsrfSmugglingProbe::REDIS, 'critical',
            ],
            // gopher PHP-FPM FastCGI RCE (port 9000 + the PHP_VALUE override set).
            'fastcgi' => [
                'url=' . rawurlencode('gopher://127.0.0.1:9000/_%01%01%00%01 PHP_VALUE allow_url_include=On auto_prepend_file=php://input'),
                SsrfSmugglingProbe::FASTCGI, 'critical',
            ],
            // gopher Memcached key poison (set framing).
            'memcached' => [
                'url=' . rawurlencode('gopher://127.0.0.1:11211/_set foo 0 0 4%0D%0Apwnd%0D%0A'),
                SsrfSmugglingProbe::MEMCACHED, 'high',
            ],
            // gopher Zabbix agent command exec.
            'zabbix' => [
                'url=' . rawurlencode('gopher://127.0.0.1:10050/_system.run[id]'),
                SsrfSmugglingProbe::ZABBIX, 'critical',
            ],
            // dict:// Redis smuggle (dict wins into the redis family via the flushall marker).
            'dict-redis' => [
                'url=' . rawurlencode('dict://127.0.0.1:6379/flushall'),
                SsrfSmugglingProbe::REDIS, 'critical',
            ],
            // generic dict:// service brute (no richer family marker).
            'dict-generic' => [
                'url=' . rawurlencode('dict://attacker.test:2628/show:db'),
                SsrfSmugglingProbe::DICT, 'high',
            ],
        ];
    }

    /** @dataProvider smugglingPayloads */
    public function test_smuggling_payload_folds_its_family_tag(string $query, string $family, string $severity): void
    {
        $verdict = $this->engine()->classify($this->probe($query), SiteProfile::empty());
        self::assertTrue($verdict->detection->matched, 'a smuggling payload must fold a signal match');
        self::assertContains('ssrf.smuggling.' . $family, $verdict->detection->tags());
        self::assertContains('protocol-smuggling', $verdict->detection->tags());
        self::assertSame($severity, $verdict->severity);
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNull($verdict->fakeHandle, 'signal-only: nothing served/faked');
    }

    /** @return array<string,array{0:string}> */
    public function benignNegatives(): array
    {
        return [
            // a benign gopher link with no smuggled command
            'gopher-link'    => ['url=' . rawurlencode('gopher://gopher.floodgap.com/1/world')],
            // dangerous command names in prose, but no wrapper scheme
            'flushall-prose' => ['note=' . rawurlencode('the flushall command clears the redis cache')],
            'config-prose'   => ['q=' . rawurlencode('how to config set dir in the nginx docs')],
            // an http:// URL to a redis port is NOT a smuggling wrapper
            'http-redis'     => ['url=' . rawurlencode('http://127.0.0.1:6379/')],
            // a system.run mention with no wrapper
            'zabbix-prose'   => ['q=' . rawurlencode('the zabbix system.run docs')],
        ];
    }

    /** @dataProvider benignNegatives */
    public function test_benign_values_do_not_fold(string $query): void
    {
        $verdict = $this->engine()->classify($this->probe($query), SiteProfile::empty());
        $smugglingTags = array_filter(
            $verdict->detection->tags(),
            static fn (string $t): bool => strpos($t, 'ssrf.smuggling.') === 0
        );
        self::assertSame([], array_values($smugglingTags), "benign must not fold a smuggling tag: {$query}");
    }

    public function test_probe_unit_returns_family_or_null(): void
    {
        self::assertSame(SsrfSmugglingProbe::REDIS,
            SsrfSmugglingProbe::detect($this->probe('url=' . rawurlencode('gopher://127.0.0.1:6379/_*1%0D%0A$8%0D%0Aflushall%0D%0A'))));
        self::assertSame(SsrfSmugglingProbe::ZABBIX,
            SsrfSmugglingProbe::detect($this->probe('url=' . rawurlencode('gopher://h:10050/_system.run[id]'))));
        self::assertNull(SsrfSmugglingProbe::detect($this->probe('url=' . rawurlencode('http://127.0.0.1:6379/'))));
        self::assertNull(SsrfSmugglingProbe::detect($this->probe('q=just+a+gopher+mention')));
    }

    public function test_served_response_byte_identical_on_a_real_route(): void
    {
        // A smuggling payload in an SSRF param must not change a served route's bytes (anti-differential).
        $hp = new Honeypot(
            new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php'),
            new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
                static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'critical',
                65536, 0, 0, true, null, null, null, 'fixed')
        );
        $payload = 'url=' . rawurlencode('gopher://127.0.0.1:6379/_*1%0D%0A$8%0D%0Aflushall%0D%0A');
        $probe = $hp->respond(new RequestContext('GET', '/.ssh/id_rsa', $payload, [], null, 'x.test'));
        $benign = $hp->respond(new RequestContext('GET', '/.ssh/id_rsa', '', [], null, 'x.test'));
        self::assertNotNull($probe);
        self::assertNotNull($benign);
        self::assertSame($benign->status, $probe->status);
        self::assertSame($benign->body, $probe->body, 'a smuggling payload must not alter a served byte');
    }
}
