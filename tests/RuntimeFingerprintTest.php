<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Closure;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\Outcome;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Rules\RulesLocator;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * FP-0262 — the runtime egress fingerprint guard. It re-scans every built decoy response before
 * serving and fails closed to the plain 404 on a detector signature, WITHOUT scanning
 * capture-reflecting rules (scanning reflected bytes would make it a two-request oracle). Plus the
 * render-corpus CI gate and the decoy-session path-anchor invariant it depends on.
 */
final class RuntimeFingerprintTest extends TestCase
{
    /** @var string */
    private $scratch = '';

    protected function setUp(): void
    {
        RulesLocator::useDataDir(null);
    }

    protected function tearDown(): void
    {
        RulesLocator::useDataDir(null);
        if ($this->scratch !== '' && is_dir($this->scratch)) {
            foreach (glob($this->scratch . '/current/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($this->scratch . '/current');
            @rmdir($this->scratch);
        }
    }

    private function respondConfig(bool $attack = true, ?Closure $authorizer = null, bool $isolated = false, bool $runtimeScan = true): Config
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            null,
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            0,
            0,
            $attack
        );
        $config->isolatedOrigin = $isolated;
        $config->reflectorAuthorizer = $authorizer;
        $config->runtimeFingerprintScan = $runtimeScan;

        return $config;
    }

    // --- the reflection exclusion: a reflected denylist token is NEVER an oracle ------------------

    public function test_reflected_denylist_token_never_changes_the_outcome(): void
    {
        // attack-xss-baseline reflects its alnum `q` marker. `912345` matches the bare-CRS-id pattern
        // `\b9\d{5}\b` and `nuclei` matches `\bnuclei\b`; if the egress guard scanned this reflecting
        // rule, `?q=912345`→404 while `?q=812345`→200 — a two-request classifier. The rule reflects
        // captures, so it is excluded from the egress scan and all three serve identically.
        $hp = Honeypot::default($this->respondConfig());
        foreach (['912345', '812345', 'nuclei'] as $marker) {
            $resp = $hp->respond(new RequestContext('GET', '/products/quick-search', 'q=' . $marker));
            self::assertNotNull($resp, "reflected marker {$marker} must still serve (no oracle)");
            self::assertSame(200, $resp->status);
            self::assertStringContainsString($marker, $resp->body, "the marker must round-trip verbatim: {$marker}");
        }
    }

    public function test_full_tag_reflector_with_a_denylist_token_is_served_on_an_isolated_origin(): void
    {
        // attack-xss reflects a full tag on an isolated origin with a vouching authorizer. The
        // reflected token contains `912345`; the rule is excluded from the egress scan, so it serves.
        $vouch = static function (RequestContext $r, string $class): bool { return true; };
        $hp = Honeypot::default($this->respondConfig(true, $vouch, true));
        $payload = '<script>912345</script>';
        $resp = $hp->respond(new RequestContext('GET', '/products/quick-search', 'q=' . $payload));
        self::assertNotNull($resp, 'a capture-reflecting rule must never be egress-scanned');
        self::assertStringContainsString($payload, $resp->body);
    }

    // --- the positive control: a non-reflecting leak is declined, fail-closed --------------------

    public function test_non_reflecting_leak_is_declined_and_the_switch_and_guard_are_honoured(): void
    {
        // A genuine leak: a NON-reflecting attack rule whose body carries a detector signature. The
        // egress guard must decline it to the plain 404 with Outcome::FINGERPRINT_LEAK.
        $this->installScratchAttackRule([
            'id' => 'attack-control-leak',
            'severity' => 'high',
            'tags' => ['control'],
            'status' => 200,
            'match' => [['in' => 'path', 'regex' => '^/fp0262-control-leak$', 'ci' => false]],
            'response' => ['headers' => [], 'body' => 'blocked by OWASP_CRS ruleset'],
        ]);
        $req = new RequestContext('GET', '/fp0262-control-leak', '');

        $obs = new RecordingObserver();
        $hp = Honeypot::default($this->respondConfig(), $obs);
        self::assertNull($hp->respond($req), 'a non-reflecting detector signature must be declined');
        self::assertSame(Outcome::FINGERPRINT_LEAK, $obs->lastReason);

        // The off-switch serves it (the static gate still covers authored bytes).
        $off = Honeypot::default($this->respondConfig(true, null, false, false));
        $served = $off->respond($req);
        self::assertNotNull($served, 'runtimeFingerprintScan=false must serve');
        self::assertStringContainsString('OWASP_CRS', $served->body);

        // Fail-closed on an unavailable guard: the injected null guard means "cannot verify" → 404.
        $obs2 = new RecordingObserver();
        $hp2 = Honeypot::default($this->respondConfig(), $obs2);
        $hp2->setFingerprintGuardForTesting(null);
        self::assertNull($hp2->respond($req), 'an unavailable guard must fail closed');
        self::assertSame(Outcome::FINGERPRINT_LEAK, $obs2->lastReason);
    }

    // --- the route path is egress-scanned too ----------------------------------------------------

    public function test_route_egress_path_is_scanned_and_fails_closed(): void
    {
        $req = new RequestContext('GET', '/.hg/hgrc', '');
        $obs = new RecordingObserver();
        $hp = Honeypot::default($this->respondConfig(), $obs);

        $served = $hp->respond($req);
        self::assertNotNull($served, 'the route decoy must serve with the real (clean) guard');
        self::assertStringContainsString('[paths]', $served->body);

        // Inject a guard that flags a token this route provably serves — the route egress scan must
        // then decline it, proving buildRouteFake() screens the synthesized body.
        $hp->setFingerprintGuardForTesting(new FingerprintGuard(['[paths]'], []));
        self::assertNull($hp->respond($req), 'a flagged route body must be declined at egress');
        self::assertSame(Outcome::FINGERPRINT_LEAK, $obs->lastReason);
    }

    // --- the render-corpus CI gate ---------------------------------------------------------------

    public function test_render_corpus_gate_passes_on_the_committed_corpus(): void
    {
        [$code, $out] = $this->runRuntimeGate([]);
        self::assertSame(0, $code, implode("\n", $out));
        self::assertStringContainsString('across 13 classes', implode("\n", $out));
    }

    public function test_render_corpus_gate_is_non_vacuous(): void
    {
        // A doctored denylist flagging a token the rendered corpus provably emits (`charset`, in
        // every text Content-Type) must fail the gate — proof it actually scans rendered output.
        $tmp = tempnam(sys_get_temp_dir(), 'fp-dl-') . '.php';
        file_put_contents($tmp, "<?php\n\nreturn ['literals' => ['charset'], 'patterns' => []];\n");
        try {
            [$code, $out] = $this->runRuntimeGate(['--denylist=' . $tmp]);
            self::assertSame(1, $code, 'a token the corpus renders must fail the gate: ' . implode("\n", $out));
        } finally {
            @unlink($tmp);
        }
    }

    // --- the invariant the reflection exclusion relies on ---------------------------------------

    public function test_path_reflecting_decoy_session_rules_have_anchored_path_matchers(): void
    {
        // The decoy-session gate reflects $r->path into the authed body / canonical-slash redirect.
        // It is NOT in the reflecting-rule set, so the egress guard DOES scan it — safe only while no
        // attacker-chosen token can reach $r->path, i.e. its path matcher is fully ^...$-anchored.
        // A future loosened regex would turn the FP-0237 body guard + this egress guard into a path
        // oracle, so pin the anchor for every panel-serving (gate) or canonical-slash decoy rule.
        $attack = require __DIR__ . '/../resources/compiled/funnypot-attack.php';
        $checked = 0;
        foreach ($attack as $rule) {
            if (!is_array($rule) || ($rule['behavior'] ?? '') !== 'decoy-session') {
                continue;
            }
            $ds = (array) ($rule['decoy-session'] ?? []);
            $reflectsPath = ($ds['mode'] ?? '') === 'gate' || !empty($ds['canonical_slash']);
            if (!$reflectsPath) {
                continue; // mint-only rules redirect to a literal path, never reflecting $r->path
            }
            $pathRegex = null;
            foreach ((array) ($rule['match'] ?? []) as $m) {
                if (($m['in'] ?? '') === 'path') {
                    $pathRegex = (string) ($m['regex'] ?? '');
                }
            }
            self::assertNotNull($pathRegex, "decoy-session rule {$rule['id']} must pin a path matcher");
            self::assertMatchesRegularExpression('/^\^.*\$$/', $pathRegex, "decoy-session rule {$rule['id']} path matcher must be ^...\$-anchored (reflects \$r->path)");
            $checked++;
        }
        self::assertGreaterThan(0, $checked, 'expected at least one path-reflecting decoy-session rule');
    }

    // --- helpers --------------------------------------------------------------------------------

    /** @param array<string,mixed> $rule */
    private function installScratchAttackRule(array $rule): void
    {
        $this->scratch = sys_get_temp_dir() . '/fp0262-rt-' . getmypid() . '-' . uniqid();
        mkdir($this->scratch . '/current', 0755, true);
        file_put_contents(
            $this->scratch . '/current/funnypot-attack.php',
            "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export([$rule], true) . ";\n"
        );
        RulesLocator::useDataDir($this->scratch);
    }

    /**
     * @param string[] $args
     * @return array{0:int,1:string[]}
     */
    private function runRuntimeGate(array $args): array
    {
        $script = dirname(__DIR__) . '/scripts/ci/check-runtime-fingerprint-safety.php';
        $cmd = 'php -d memory_limit=1G ' . escapeshellarg($script);
        foreach ($args as $a) {
            $cmd .= ' ' . escapeshellarg($a);
        }
        $out = [];
        $code = 0;
        exec($cmd . ' 2>&1', $out, $code);

        return [$code, $out];
    }
}

/** Records the last onOutcome reason for the egress-guard assertions. */
final class RecordingObserver implements Observer
{
    /** @var string|null */
    public $lastReason = null;

    public function onDetection(RequestContext $r, Detection $detection): void
    {
    }

    public function shouldRespond(RequestContext $r, Detection $detection): bool
    {
        return true;
    }

    public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
    {
        $this->lastReason = $reason;
    }
}
