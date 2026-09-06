<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\BotSignalSet;
use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\SynthesisConfig;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\TemplateMatch;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * Phase 0: the pure two-phase value types exist, default sensibly, and round-trip as
 * serializable data (they must survive crossing the policy boundary + becoming telemetry).
 */
final class ValueTypesTest extends TestCase
{
    public function test_botsignalset_is_empty_and_zero_weight_by_default(): void
    {
        $s = BotSignalSet::empty();

        self::assertSame([], $s->flags);
        self::assertSame(0, $s->weight);
        self::assertSame(BotSignalSet::UA_UNKNOWN, $s->uaClass);
        self::assertSame('', $s->fingerprint);
        self::assertFalse($s->anyFired());
    }

    public function test_botsignalset_round_trips_as_pure_data(): void
    {
        $s = new BotSignalSet(
            [BotSignalSet::MISSING_ACCEPT => true, BotSignalSet::EMPTY_USER_AGENT => true],
            15,
            BotSignalSet::UA_EMPTY,
            'get|a,b,c'
        );

        $back = BotSignalSet::fromArray($s->toArray());

        self::assertEquals($s, $back);
        self::assertTrue($back->anyFired());
        self::assertTrue($back->has(BotSignalSet::MISSING_ACCEPT));
        self::assertFalse($back->has(BotSignalSet::MISSING_ACCEPT_LANGUAGE));
        self::assertSame(15, $back->weight);

        // Survives JSON (the telemetry transport shape, decision T).
        self::assertEquals($s, BotSignalSet::fromArray(json_decode(json_encode($s->toArray()), true)));
    }

    public function test_fakehandle_route_round_trips(): void
    {
        $h = FakeHandle::route('GET /.git/config');

        self::assertSame(FakeHandle::KIND_ROUTE, $h->kind);
        self::assertSame('GET /.git/config', $h->key);
        self::assertNull($h->ruleId);
        self::assertEquals($h, FakeHandle::fromArray($h->toArray()));
    }

    public function test_fakehandle_attack_carries_captures(): void
    {
        $h = FakeHandle::attack('attack-lfi-unix', [0 => 'match', 1 => 'etc/passwd']);

        self::assertSame(FakeHandle::KIND_ATTACK, $h->kind);
        self::assertSame('attack-lfi-unix', $h->ruleId);
        self::assertSame('etc/passwd', $h->captures[1]);
        self::assertEquals($h, FakeHandle::fromArray($h->toArray()));
        self::assertEquals($h, FakeHandle::fromArray(json_decode(json_encode($h->toArray()), true)));
    }

    public function test_fakehandle_method_round_trips(): void
    {
        // FP-0011: a bounded method-coverage handle reuses the `key` field, carries no captures or
        // intent, and survives the JSON telemetry hop unchanged.
        $h = FakeHandle::method('OPTIONS /wp-login.php');

        self::assertSame(FakeHandle::KIND_METHOD, $h->kind);
        self::assertSame('OPTIONS /wp-login.php', $h->key);
        self::assertNull($h->ruleId);
        self::assertNull($h->paramIntent);
        self::assertSame(
            ['kind' => 'method', 'key' => 'OPTIONS /wp-login.php', 'ruleId' => null, 'captures' => []],
            $h->toArray()
        );
        self::assertEquals($h, FakeHandle::fromArray($h->toArray()));
        self::assertEquals($h, FakeHandle::fromArray(json_decode(json_encode($h->toArray()), true)));
    }

    public function test_fakehandle_route_without_intent_serializes_exactly_as_before(): void
    {
        // The paramIntent key is absent unless present, so legacy route arrays are byte-identical.
        self::assertSame(
            ['kind' => 'route', 'key' => 'GET /x', 'ruleId' => null, 'captures' => []],
            FakeHandle::route('GET /x')->toArray()
        );
    }

    public function test_fakehandle_route_with_intent_round_trips(): void
    {
        $intent = \Funnypot\Core\Reaction\ParamIntent::create('search-result', 'q', 'hello');
        self::assertNotNull($intent);
        $h = FakeHandle::route('GET /x', $intent);

        self::assertSame(
            ['kind' => 'route', 'key' => 'GET /x', 'ruleId' => null, 'captures' => [], 'paramIntent' => ['v' => 1, 'kind' => 'search-result', 'key' => 'q', 'value' => 'hello']],
            $h->toArray()
        );
        self::assertEquals($h, FakeHandle::fromArray($h->toArray()));
        self::assertEquals($h, FakeHandle::fromArray(json_decode(json_encode($h->toArray()), true)));
    }

    /**
     * @dataProvider malformedIntentProvider
     * @param mixed $paramIntent
     */
    public function test_fakehandle_malformed_intent_degrades_to_null($paramIntent): void
    {
        $data = ['kind' => 'route', 'key' => 'GET /x', 'ruleId' => null, 'captures' => [], 'paramIntent' => $paramIntent];
        self::assertNull(FakeHandle::fromArray($data)->paramIntent);
    }

    /** @return iterable<string,array{0:mixed}> */
    public static function malformedIntentProvider(): iterable
    {
        yield 'string' => ['not-an-array'];
        yield 'positional list' => [['search-result', 'q', 'hello']];
        yield 'unknown version' => [['v' => 2, 'kind' => 'search-result', 'key' => 'q', 'value' => 'x']];
        yield 'unknown kind' => [['v' => 1, 'kind' => 'nope', 'key' => 'q', 'value' => 'x']];
        yield 'key kind mismatch' => [['v' => 1, 'kind' => 'search-result', 'key' => 'cmd', 'value' => 'x']];
        yield 'oversized value' => [['v' => 1, 'kind' => 'search-result', 'key' => 'q', 'value' => str_repeat('a', 257)]];
        yield 'extra field' => [['v' => 1, 'kind' => 'search-result', 'key' => 'q', 'value' => 'x', 'extra' => 1]];
    }

    public function test_fakehandle_non_route_kind_never_carries_an_intent(): void
    {
        $intent = \Funnypot\Core\Reaction\ParamIntent::create('search-result', 'q', 'hello');
        self::assertNotNull($intent);
        // Construct an attack handle with an intent argument: it must be forced null.
        $attack = new FakeHandle(FakeHandle::KIND_ATTACK, null, 'attack-x', [], $intent);
        self::assertNull($attack->paramIntent);
        self::assertArrayNotHasKey('paramIntent', $attack->toArray());
    }

    public function test_siteprofile_empty_has_no_stack_and_no_oracle(): void
    {
        $p = SiteProfile::empty();

        self::assertSame([], $p->declaredStack);
        self::assertNull($p->routeExists);
        // No oracle ⇒ never a real route (the safe default; today's FALLBACK behavior).
        self::assertFalse($p->hasRoute('GET', '/wp-login.php'));
    }

    public function test_siteprofile_oracle_is_consulted(): void
    {
        $p = new SiteProfile(['php', 'nginx'], static function (string $method, string $path): bool {
            return $method === 'GET' && $path === '/real';
        });

        self::assertSame(['php', 'nginx'], $p->declaredStack);
        self::assertTrue($p->hasRoute('GET', '/real'));
        self::assertFalse($p->hasRoute('GET', '/fake'));
        self::assertFalse($p->hasRoute('POST', '/real'));
    }

    public function test_verdict_defaults_and_clean_factory(): void
    {
        $v = Verdict::clean();

        self::assertSame(Verdict::CLEAN, $v->classification);
        self::assertTrue($v->isClean());
        self::assertTrue($v->detection->isEmpty());
        self::assertSame(0, $v->anomaly);
        self::assertNull($v->fakeHandle);
        self::assertInstanceOf(BotSignalSet::class, $v->signals);
    }

    public function test_verdict_clean_folds_signal_weight_into_anomaly(): void
    {
        $signals = new BotSignalSet([BotSignalSet::MISSING_ACCEPT => true], 5, BotSignalSet::UA_SCRIPT, 'fp');
        $v = Verdict::clean($signals);

        self::assertSame(Verdict::CLEAN, $v->classification);
        self::assertSame(5, $v->anomaly);
        self::assertSame($signals, $v->signals);
    }

    public function test_verdict_carries_detection_and_handle(): void
    {
        $detection = new Detection(true, [new TemplateMatch('git-config', 'medium', ['git'], 'Git')], 'GET /.git/config', 'medium');
        $v = new Verdict(
            Verdict::SCANNER_PROBE,
            $detection,
            'medium',
            0,
            BotSignalSet::empty(),
            FakeHandle::route('GET /.git/config')
        );

        self::assertSame(Verdict::SCANNER_PROBE, $v->classification);
        self::assertFalse($v->isClean());
        self::assertSame('medium', $v->severity);
        self::assertSame(FakeHandle::KIND_ROUTE, $v->fakeHandle->kind);

        $array = $v->toArray();
        self::assertSame(Verdict::SCANNER_PROBE, $array['classification']);
        self::assertSame(['git-config'], $array['detection']['templateIds']);
        self::assertSame('GET /.git/config', $array['fakeHandle']['key']);
    }

    public function test_classification_constants_are_the_documented_enum(): void
    {
        self::assertSame('clean', Verdict::CLEAN);
        self::assertSame('scanner-probe', Verdict::SCANNER_PROBE);
        self::assertSame('attack-class', Verdict::ATTACK_CLASS);
        self::assertSame('suspicious', Verdict::SUSPICIOUS);
    }

    public function test_synthesisconfig_defaults_and_from_config(): void
    {
        $c = new SynthesisConfig();
        self::assertSame('high', $c->severityCeiling);
        self::assertSame(65536, $c->maxBodyBytes);
        self::assertTrue($c->nucleiReflection);
        self::assertFalse($c->attackEmulation);

        $derived = SynthesisConfig::fromConfig(new Config(
            'detect',                            // mode
            null,                                // gate
            'matched-only',                      // pathScope
            null,                                // personaSeed
            'coherent',                          // personaBreadth
            \Funnypot\Core\Response\Style::MINIMAL,   // responseStyle
            'critical',                          // severityCeiling
            1024,                                // maxBodyBytes
            0,                                   // latencyMs
            0,                                   // latencyJitterMs
            true,                                // attackEmulation
            null,                                // trustedBypass
            null,                                // killSwitch
            null,                                // probeSignature
            '',                                  // seedSalt
            ['t-crit'],                          // exclude
            false,                               // nucleiReflection
            'nginx',                             // serverHeader
            'PHP/8.2'                            // poweredBy
        ));
        self::assertSame('critical', $derived->severityCeiling);
        self::assertTrue($derived->attackEmulation);
        self::assertSame(['t-crit'], $derived->exclude);
        self::assertFalse($derived->nucleiReflection);
        self::assertSame(1024, $derived->maxBodyBytes);
        self::assertSame('nginx', $derived->serverHeader);
        self::assertSame('PHP/8.2', $derived->poweredBy);
    }
}
