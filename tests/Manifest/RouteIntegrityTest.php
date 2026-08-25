<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Manifest;

use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Manifest\ManifestBuilder;
use Funnypot\Core\Manifest\RouteIntegrity;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * Route-integrity lint (FP-0002). Two halves:
 *
 *   1. The lint itself — method-aware collision, cross-family shadow, and dangling-self-link checks
 *      over the derived manifest, plus the escape-hatch suppression. The make-or-break case is the
 *      phpMyAdmin GET/HEAD gate + POST login co-owning /phpmyadmin by DISJOINT methods: legit, must
 *      NOT flag. A relative self-link must fail outright. And `bin/funnypot lint-routes` must exit 0
 *      over the committed artifacts + committed escape hatches (so CI stays green).
 *   2. Per-family precedence smoke — real classify()/respond() assertions that the winning decoy is
 *      the expected one, so a routing regression surfaces here in the normal suite.
 */
final class RouteIntegrityTest extends TestCase
{
    /** @var array<string,mixed> */
    private static $manifest;

    /** @var string */
    private static $root;

    public static function setUpBeforeClass(): void
    {
        self::$root = dirname(__DIR__, 2);
        self::$manifest = (new ManifestBuilder())->build(ManifestBuilder::defaultPaths(self::$root));
    }

    /** Run the lint with empty escape hatches — the raw findings, before any suppression. */
    private function rawFindings(): array
    {
        $result = (new RouteIntegrity())->analyze(self::$manifest, array(
            'disabled' => array(), 'priority_overrides' => array(), 'accepted' => array(),
        ));

        return $result['findings'];
    }

    /**
     * @param array<int,array<string,mixed>> $findings
     * @return array<int,array<string,mixed>>
     */
    private function only(array $findings, string $check, string $severity): array
    {
        $out = array();
        foreach ($findings as $f) {
            if ($f['check'] === $check && $f['severity'] === $severity) {
                $out[] = $f;
            }
        }

        return $out;
    }

    // --- the checks -------------------------------------------------------------------------

    public function test_phpmyadmin_gate_and_login_do_not_collide_by_disjoint_methods(): void
    {
        // The regression: gate (GET/HEAD) and login (POST) co-own /phpmyadmin. Method-awareness must
        // keep this off the collision report — no FAIL naming either id.
        $flagged = array();
        foreach ($this->only($this->rawFindings(), RouteIntegrity::CHECK_COLLISION, RouteIntegrity::FAIL) as $f) {
            $flagged[] = $f['a'];
            $flagged[] = $f['b'];
        }
        self::assertNotContains('attack-phpmyadmin-gate', $flagged, 'gate must not be in a collision pair');
        self::assertNotContains('attack-phpmyadmin-login', $flagged, 'login must not be in a collision pair');
    }

    public function test_no_true_collisions_over_the_committed_manifest(): void
    {
        // Same-family first-match ordering and method-disjoint co-ownership are legit; there is no
        // cross-family same-tier same-method claim in the current corpus.
        self::assertSame(
            array(),
            $this->only($this->rawFindings(), RouteIntegrity::CHECK_COLLISION, RouteIntegrity::FAIL),
            'unexpected true collision(s) — see message'
        );
    }

    public function test_no_unintended_cross_family_shadows(): void
    {
        // Every owns_path override is same-family or carries a declared intent tag; none silently
        // masks a different-family route.
        self::assertSame(
            array(),
            $this->only($this->rawFindings(), RouteIntegrity::CHECK_SHADOW, RouteIntegrity::FAIL)
        );
    }

    public function test_relative_self_link_fails_outright(): void
    {
        // A relative form action (the phpMyAdmin failure mode) is a FAIL independent of where it
        // resolves — before any escape-hatch suppression.
        $found = false;
        foreach ($this->only($this->rawFindings(), RouteIntegrity::CHECK_DANGLING, RouteIntegrity::FAIL) as $f) {
            if ($f['a'] === 'attack-phpmyadmin-gate' && $f['path'] === 'index.php') {
                $found = true;
            }
        }
        self::assertTrue($found, 'the relative index.php self-link is flagged FAIL');
    }

    public function test_accepted_escape_hatch_downgrades_a_finding(): void
    {
        // An accepted entry turns a FAIL into an ACCEPTED (non-gating) finding, carrying its reason.
        $result = (new RouteIntegrity())->analyze(self::$manifest, array(
            'accepted' => array(array(
                'check' => 'dangling',
                'a' => 'attack-phpmyadmin-gate',
                'path' => 'index.php',
                'reason' => 'test-accept',
            )),
        ));
        $seen = false;
        foreach ($result['findings'] as $f) {
            if ($f['a'] === 'attack-phpmyadmin-gate' && $f['path'] === 'index.php') {
                self::assertSame(RouteIntegrity::ACCEPTED, $f['severity']);
                self::assertSame('test-accept', $f['accepted_reason']);
                $seen = true;
            }
        }
        self::assertTrue($seen);
    }

    public function test_disabled_missing_id_is_reported(): void
    {
        $result = (new RouteIntegrity())->analyze(self::$manifest, array('disabled' => array('no-such-decoy-id')));
        self::assertContains('no-such-decoy-id', $result['disabled_missing']);
    }

    public function test_lint_routes_command_exits_zero_over_committed_artifacts(): void
    {
        // The authority: the shipped command over the committed artifacts + committed escape hatches
        // must be clean, so CI can gate on its exit code beside check-fingerprint-safety.php.
        $bin = self::$root . '/bin/funnypot';
        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($bin) . ' lint-routes 2>&1';
        $out = array();
        $code = 0;
        exec($cmd, $out, $code);
        self::assertSame(0, $code, "lint-routes must exit 0:\n" . implode("\n", $out));
    }

    // --- per-family precedence smoke (check d) ----------------------------------------------

    /** A respond-mode engine with the attack + param tiers live, pinned open, for precedence probes. */
    private function engine(): Honeypot
    {
        $gate = static function (RequestContext $r): bool {
            return true;
        };

        return new Honeypot(
            new PhpArrayStore(require self::$root . '/resources/compiled/nuclei-index.full.php'),
            new Config('respond', $gate, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0, true)
        );
    }

    private function servedRuleId(RequestContext $r): string
    {
        $resp = $this->engine()->respond($r);
        self::assertNotNull($resp, 'a decoy served the probe');
        self::assertNotNull($resp->servedBy, 'the winning handle is surfaced');

        return $resp->servedBy->kind === FakeHandle::KIND_ROUTE
            ? (string) $resp->servedBy->key
            : (string) $resp->servedBy->ruleId;
    }

    public function test_precedence_phpmyadmin_gate_and_login(): void
    {
        self::assertSame('attack-phpmyadmin-gate', $this->servedRuleId(new RequestContext('GET', '/phpmyadmin')));
        self::assertSame(
            'attack-phpmyadmin-login',
            $this->servedRuleId(new RequestContext('POST', '/phpmyadmin', '', array(), 'pma_username=admin&pma_password=secret'))
        );
    }

    public function test_precedence_phpmyadmin_form_action_target_stays_in_family(): void
    {
        // The canonical-slash-resolved form-action target (/phpmyadmin/index.php) must serve a
        // phpMyAdmin-family decoy — a regression here is exactly the fall-through bug this lint guards.
        self::assertSame('attack-phpmyadmin-gate', $this->servedRuleId(new RequestContext('GET', '/phpmyadmin/index.php')));
    }

    public function test_precedence_ai_ollama_tags_owns_path(): void
    {
        self::assertSame('attack-ai-ollama-tags', $this->servedRuleId(new RequestContext('GET', '/api/tags')));
    }

    public function test_precedence_corpus_key_serves_a_route_handle(): void
    {
        $resp = $this->engine()->respond(new RequestContext('GET', '/.git/config'));
        self::assertNotNull($resp);
        self::assertNotNull($resp->servedBy);
        self::assertSame(FakeHandle::KIND_ROUTE, $resp->servedBy->kind);
        self::assertSame('GET /.git/config', $resp->servedBy->key);
    }
}
