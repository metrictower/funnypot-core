<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0086 — a hostile query/body payload aimed at a REAL declared route (which the M2 no-shadow guard
 * classifies CLEAN) must reach ATTACK_CLASS when payloadInspection is opted in, WITHOUT serving any
 * fabricated bytes (detection only) and WITHOUT reintroducing path-driven false positives. Default off
 * keeps every existing deployment byte/verdict-identical.
 */
final class PayloadInspectionTest extends TestCase
{
    /** A profile that declares every path a genuine host route (drives the M2 no-shadow guard). */
    private function realRouteProfile(): SiteProfile
    {
        return new SiteProfile([], static function (): bool {
            return true;
        });
    }

    private function honeypot(bool $payloadInspection, bool $attackEmulation): Honeypot
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool {
                return true;
            },
            'matched-only',
            null,
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            0,
            0,
            $attackEmulation
        );
        $config->payloadInspection = $payloadInspection;

        return Honeypot::default($config);
    }

    /** A corpus path used as a stand-in real route; the query carries the payload. */
    private function realRouteRequest(string $query): RequestContext
    {
        return new RequestContext('GET', '/wp-login.php', $query);
    }

    /**
     * @dataProvider hostilePayloads
     * Each attack class (and an encoded evasion) aimed at a real route must reach ATTACK_CLASS.
     */
    public function test_hostile_payload_on_a_real_route_reaches_attack_class_when_opted_in(string $query, ?string $body): void
    {
        $hp = $this->honeypot(true, false);
        $verdict = $hp->classify(new RequestContext('GET', '/wp-login.php', $query, [], $body), $this->realRouteProfile());
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
    }

    /** @return array<string,array{0:string,1:?string}> */
    public static function hostilePayloads(): array
    {
        return [
            'sqli'          => ['redirect=1 union select 1 from users', null],
            'lfi'           => ['file=../../../../etc/passwd', null],
            'xss'           => ['q=<script>alert(1)</script>', null],
            'rce'           => ['cmd=;cat /etc/passwd', null],
            'sqli in body'  => ['', 'name=1 union select password from users'],
            // Encoded evasion exposed by the FP-0356 decode fold (HTML-entity), on a real route.
            'entity-encoded sqli' => ['q=1 union&#x20;select 1', null],
        ];
    }

    public function test_benign_payload_on_a_real_route_stays_clean(): void
    {
        $hp = $this->honeypot(true, false);
        $verdict = $hp->classify($this->realRouteRequest('q=hello world&page=2'), $this->realRouteProfile());
        self::assertSame(Verdict::CLEAN, $verdict->classification, 'benign query on a real route must stay CLEAN');
    }

    public function test_no_payload_on_a_real_route_stays_clean(): void
    {
        // The common case: a real route with no query/body pays ~nothing and stays CLEAN.
        $hp = $this->honeypot(true, false);
        $verdict = $hp->classify(new RequestContext('GET', '/wp-login.php', ''), $this->realRouteProfile());
        self::assertSame(Verdict::CLEAN, $verdict->classification);
    }

    public function test_default_off_leaves_the_m2_guard_intact(): void
    {
        // Same hostile request, payloadInspection OFF -> the M2 guard classifies CLEAN, exactly as
        // before FP-0086. This is the backward-compatibility guarantee.
        $hp = $this->honeypot(false, false);
        $verdict = $hp->classify($this->realRouteRequest('redirect=1 union select 1 from users'), $this->realRouteProfile());
        self::assertSame(Verdict::CLEAN, $verdict->classification, 'default-off must preserve the M2 no-shadow CLEAN verdict');
    }

    public function test_payload_inspection_only_serves_nothing(): void
    {
        // MF1/MF2: a payloadInspection-only build (attackEmulation OFF) may CLASSIFY ATTACK_CLASS but
        // must SERVE nothing — detect mode changes no bytes.
        $hp = $this->honeypot(true, false);
        $profile = $this->realRouteProfile();
        $verdict = $hp->classify($this->realRouteRequest('redirect=1 union select 1 from users'), $profile);

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNull($hp->synthesize($verdict, $profile, 'seed'), 'payloadInspection-only must synthesize nothing');
        if ($verdict->fakeHandle !== null) {
            self::assertNull($hp->synthesizeFromHandle($verdict->fakeHandle, $profile, 'seed'), 'payloadInspection-only must serve no attack bytes');
        }
    }

    public function test_serving_is_restored_when_attack_emulation_is_on(): void
    {
        // With attackEmulation ON, the same real-route payload verdict CAN serve — proving the serving
        // gate is attackEmulation, not the mere presence of a built emulator.
        $hp = $this->honeypot(true, true);
        $profile = $this->realRouteProfile();
        $verdict = $hp->classify($this->realRouteRequest('redirect=1 union select 1 from users'), $profile);

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($hp->synthesize($verdict, $profile, 'seed'), 'attackEmulation ON must serve the fake');
    }

    public function test_path_like_query_value_does_not_false_positive(): void
    {
        // A benign query value that merely LOOKS path-ish must not hit ATTACK_CLASS — path-stripping
        // + the payload-eligible subset mean no path-pinned rule can fire through this branch.
        $hp = $this->honeypot(true, false);
        foreach (['file=my.report/2024.pdf', 'next=/dashboard/home', 'ref=/blog/posts/hello-world'] as $q) {
            $verdict = $hp->classify($this->realRouteRequest($q), $this->realRouteProfile());
            self::assertSame(Verdict::CLEAN, $verdict->classification, "benign path-like query must stay CLEAN: {$q}");
        }
    }

    public function test_payload_scan_is_not_catastrophically_slow(): void
    {
        // A coarse regression tripwire (NOT a benchmark): 300 real-route payload classifications must
        // complete well under a generous wall bound. Catches an accidental full-corpus/unbounded scan
        // without being flaky on a loaded CI runner.
        $hp = $this->honeypot(true, false);
        $profile = $this->realRouteProfile();
        $req = $this->realRouteRequest('redirect=1 union select 1 from users');
        $start = microtime(true);
        for ($i = 0; $i < 300; $i++) {
            $hp->classify($req, $profile);
        }
        self::assertLessThan(5.0, microtime(true) - $start, '300 payload classifications should be well under 5s');
    }

    public function test_non_route_behavior_is_identical_with_and_without_payload_inspection(): void
    {
        // A non-declared path (empty profile): payloadInspection is scoped to REAL routes, so it must
        // not change the verdict for a non-route request.
        $req = new RequestContext('GET', '/some/unlikely/path/xyz', 'redirect=1 union select 1');
        $off = $this->honeypot(false, false)->classify($req, SiteProfile::empty());
        $on = $this->honeypot(true, false)->classify($req, SiteProfile::empty());
        self::assertSame($off->classification, $on->classification, 'payloadInspection must not change non-route classification');
    }
}
