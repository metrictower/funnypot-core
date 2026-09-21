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

    public function test_hostile_payload_on_a_real_route_reaches_attack_class_when_opted_in(): void
    {
        $hp = $this->honeypot(true, false);
        $verdict = $hp->classify($this->realRouteRequest('redirect=1 union select 1 from users'), $this->realRouteProfile());
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, 'a SQLi payload to a real route must classify ATTACK_CLASS under payloadInspection');
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
