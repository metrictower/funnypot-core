<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * Phase 1: classify() is the single detection path — today's detect() widened to run the
 * attack matcher and to consult the SiteProfile real-route oracle. For every routed case its
 * .detection must equal today's detect(); the new classification/handle/oracle behavior is
 * additive.
 */
final class ClassifyTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    private function engine(bool $attack = false): Honeypot
    {
        return new Honeypot($this->store(), new Config(
            'detect',                            // mode
            null,                                // gate
            'matched-only',                      // pathScope
            null,                                // personaSeed
            'coherent',                          // personaBreadth
            \Funnypot\Core\Response\Style::MINIMAL,   // responseStyle
            'high',                              // severityCeiling
            65536,                               // maxBodyBytes
            0,                                   // latencyMs
            0,                                   // latencyJitterMs
            $attack                              // attackEmulation
        ));
    }

    public function test_classify_detection_matches_detect_for_a_routed_probe(): void
    {
        $engine = $this->engine();
        $r = new RequestContext('GET', '/.git/config');

        $verdict = $engine->classify($r, SiteProfile::empty());

        self::assertEquals($engine->detect($r), $verdict->detection);
        self::assertSame(['git-config'], $verdict->detection->templateIds());
    }

    public function test_routed_probe_classifies_scanner_probe_with_route_handle(): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());

        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertSame('medium', $verdict->severity);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ROUTE, $verdict->fakeHandle->kind);
        self::assertSame('GET /.git/config', $verdict->fakeHandle->key);
    }

    public function test_clean_miss_classifies_clean_with_no_handle(): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', '/totally/legit/page'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertTrue($verdict->detection->isEmpty());
        self::assertNull($verdict->fakeHandle);
    }

    public function test_attack_payload_on_unrouted_path_classifies_attack_class(): void
    {
        $r = new RequestContext('GET', '/nope', 'file=../../../../etc/passwd');

        $verdict = $this->engine(true)->classify($r, SiteProfile::empty());

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);
        self::assertSame('attack-lfi-unix', $verdict->fakeHandle->ruleId);
        self::assertSame(['attack-lfi-unix'], $verdict->detection->templateIds());
    }

    public function test_attack_matcher_is_off_when_attack_emulation_disabled(): void
    {
        // detect()-parity: with attack emulation off, an injection on an unrouted path is clean.
        $r = new RequestContext('GET', '/nope', 'file=../../../../etc/passwd');

        $verdict = $this->engine(false)->classify($r, SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
    }

    public function test_real_route_oracle_demotes_a_would_be_probe_to_clean(): void
    {
        $profile = new SiteProfile(['git'], static function (string $method, string $path): bool {
            return $path === '/.git/config';
        });

        $verdict = $this->engine()->classify(new RequestContext('GET', '/.git/config'), $profile);

        // A live route on the host is never shadowed — no probe, no handle.
        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
        self::assertTrue($verdict->detection->isEmpty());
    }

    public function test_sig1_root_entry_classifies_clean_but_keeps_a_handle(): void
    {
        // A root/homepage-class entry (all bundles sig=1) is an ordinary-visitor path: classify
        // clean natively (no probe signature is a policy input), yet keep the route handle so the
        // facade/policy can still synthesize when it does supply one.
        $store = new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => ['t-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A']],
            'routes' => [
                'GET /root' => ['b' => [
                    ['s' => 200, 'bw' => ['ROOT'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'low', 'sig' => 1, 't' => ['t-a']],
                ]],
            ],
        ]);
        $engine = new Honeypot($store);

        $verdict = $engine->classify(new RequestContext('GET', '/root'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame('GET /root', $verdict->fakeHandle->key);
        // detect() still signals the underlying match (unchanged).
        self::assertSame(['t-a'], $verdict->detection->templateIds());
    }

    public function test_detect_delegates_to_classify(): void
    {
        $engine = $this->engine();

        foreach (['/.git/config', '/totally/legit/page', '/webpack.config.js'] as $path) {
            $r = new RequestContext('GET', $path);
            self::assertEquals(
                $engine->classify($r, SiteProfile::empty())->detection,
                $engine->detect($r),
                "detect() must equal classify().detection for {$path}"
            );
        }
    }

    /**
     * Build an engine over the shipped store with an explicit exclude (serving) and/or
     * ignoreTemplates (detection) set — the two are distinct axes on Config.
     *
     * @param string[] $exclude
     * @param string[] $ignore
     */
    private function engineFor(array $exclude = [], array $ignore = [], ?PhpArrayStore $store = null): Honeypot
    {
        return new Honeypot($store ?? $this->store(), new Config(
            'detect', null, 'matched-only', null, 'coherent',
            \Funnypot\Core\Response\Style::MINIMAL, 'high', 65536, 0, 0,
            false,     // attackEmulation
            null,      // trustedBypass
            null,      // killSwitch
            null,      // probeSignature
            '',        // seedSalt
            $exclude,  // exclude — never SERVE these
            true,      // nucleiReflection
            null,      // serverHeader
            null,      // poweredBy
            null,      // honeytokenKey
            null,      // deploySeed
            null,      // decoySessionKey
            $ignore    // ignoreTemplates — never let these DRIVE a detection
        ));
    }

    public function test_ignore_by_id_degrades_a_single_match_probe_to_clean(): void
    {
        $r = new RequestContext('GET', '/.git/config');

        // Baseline: without ignore this path is a probe on git-config.
        self::assertSame(
            Verdict::SCANNER_PROBE,
            $this->engineFor()->classify($r, SiteProfile::empty())->classification
        );

        $verdict = $this->engineFor([], ['git-config'])->classify($r, SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertTrue($verdict->detection->isEmpty());
        self::assertFalse($verdict->detection->matched);
        self::assertSame([], $verdict->detection->templateIds());
        self::assertNull($verdict->fakeHandle);
    }

    public function test_ignore_by_tag_degrades_probe_to_clean(): void
    {
        // git-config carries the 'git' tag; ignoring the tag suppresses the id too.
        $verdict = $this->engineFor([], ['git'])
            ->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertTrue($verdict->detection->isEmpty());
    }

    public function test_a_template_not_in_ignore_is_unaffected(): void
    {
        // Ignoring an unrelated id/tag leaves git-config driving the detection as before.
        $verdict = $this->engineFor([], ['some-other-template', 'unrelated-tag'])
            ->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());

        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertSame(['git-config'], $verdict->detection->templateIds());
    }

    public function test_ignore_drops_from_evidence_but_a_remaining_match_still_fires(): void
    {
        // Two templates match one path; ignoring one leaves the other as evidence (Option (a)).
        $store = new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                'noisy' => ['sev' => 'low', 'tags' => ['miscellaneous'], 'name' => 'Noisy'],
                'real' => ['sev' => 'high', 'tags' => ['exposure'], 'name' => 'Real'],
            ],
            'routes' => [
                'GET /multi' => ['b' => [
                    ['s' => 200, 'bw' => ['X'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'high', 'sig' => 0, 't' => ['noisy', 'real']],
                ]],
            ],
        ]);
        $r = new RequestContext('GET', '/multi');

        $verdict = $this->engineFor([], ['noisy'], $store)->classify($r, SiteProfile::empty());

        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertTrue($verdict->detection->matched);
        self::assertSame(['real'], $verdict->detection->templateIds());

        // Ignoring both matches empties the evidence and degrades to CLEAN.
        $both = $this->engineFor([], ['noisy', 'real'], $store)->classify($r, SiteProfile::empty());
        self::assertSame(Verdict::CLEAN, $both->classification);
        self::assertTrue($both->detection->isEmpty());
    }

    public function test_ignore_works_by_tag_on_a_multi_match_entry(): void
    {
        // The whole 'miscellaneous' tag is the noise source; ignoring it drops only that template.
        $store = new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                'noisy' => ['sev' => 'low', 'tags' => ['miscellaneous'], 'name' => 'Noisy'],
                'real' => ['sev' => 'high', 'tags' => ['exposure'], 'name' => 'Real'],
            ],
            'routes' => [
                'GET /multi' => ['b' => [
                    ['s' => 200, 'bw' => ['X'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'high', 'sig' => 0, 't' => ['noisy', 'real']],
                ]],
            ],
        ]);

        $verdict = $this->engineFor([], ['miscellaneous'], $store)
            ->classify(new RequestContext('GET', '/multi'), SiteProfile::empty());

        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertSame(['real'], $verdict->detection->templateIds());
    }

    public function test_exclude_and_ignore_are_independent(): void
    {
        $r = new RequestContext('GET', '/.git/config');

        // exclude governs SERVING only: it must NOT suppress the detection.
        $excluded = $this->engineFor(['git-config'], [])->classify($r, SiteProfile::empty());
        self::assertSame(Verdict::SCANNER_PROBE, $excluded->classification);
        self::assertSame(['git-config'], $excluded->detection->templateIds());

        // ignoreTemplates governs DETECTION only: it degrades to CLEAN, and does so even when a
        // different id is the one excluded-from-serving — the two lists never cross-talk.
        $ignored = $this->engineFor(['unrelated'], ['git-config'])->classify($r, SiteProfile::empty());
        self::assertSame(Verdict::CLEAN, $ignored->classification);
        self::assertTrue($ignored->detection->isEmpty());
    }

    /** A store that keys only GET /xmlrpc.php (a non-root bundle) — the shadow the override must beat. */
    private function xmlrpcShadowStore(): PhpArrayStore
    {
        return new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [],
            'routes' => ['GET /xmlrpc.php' => ['b' => [['sig' => 2]]]],
        ]);
    }

    private function xmlrpcEngine(): Honeypot
    {
        return new Honeypot($this->xmlrpcShadowStore(), new Config(
            'detect', null, 'matched-only', null, 'coherent',
            \Funnypot\Core\Response\Style::MINIMAL, 'critical', 65536, 0, 0,
            true   // attackEmulation ON
        ));
    }

    public function test_owned_bare_xmlrpc_post_overrides_static_stub(): void
    {
        $body = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>';
        $verdict = $this->xmlrpcEngine()->classify(
            new RequestContext('POST', '/xmlrpc.php', '', [], $body),
            SiteProfile::empty()
        );

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);
    }

    public function test_owned_get_xmlrpc_also_request_aware(): void
    {
        // A GET to /xmlrpc.php: rule 27 (attack-wp-xmlrpc-get) matches GET-ending-/xmlrpc.php and
        // answers request-aware (405/RSD), so the override beats the static store stub here too —
        // observed behavior, not a fallback case (see WpXmlrpcEmulatorTest for the decline path).
        $verdict = $this->xmlrpcEngine()->classify(
            new RequestContext('GET', '/xmlrpc.php'),
            SiteProfile::empty()
        );

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);
    }
}
