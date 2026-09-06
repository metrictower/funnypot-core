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

    // --- synthetic-manifest fixtures --------------------------------------------------------

    /**
     * Analyze a minimal schema-1 manifest (no corpus unless given) with empty escape hatches.
     *
     * @param array<int,array<string,mixed>> $bandA
     * @param array<string,array<string,string>> $corpusIndex
     * @return array<int,array<string,mixed>>
     */
    private function synth(array $bandA, array $corpusIndex = array()): array
    {
        $manifest = array('bandA' => $bandA, 'corpus' => array('index' => $corpusIndex));
        $result = (new RouteIntegrity())->analyze($manifest, array(
            'disabled' => array(), 'priority_overrides' => array(), 'accepted' => array(),
        ));

        return $result['findings'];
    }

    /**
     * @param array<int,array<string,string>> $routes  owned_routes
     * @param array<int,array<string,mixed>> $links   outbound_links
     * @return array<string,mixed>
     */
    private function rec(string $id, string $family, array $routes, array $links = array()): array
    {
        return array('id' => $id, 'family' => $family, 'tier' => 'attack', 'tags' => array(),
            'owned_routes' => $routes, 'outbound_links' => $links);
    }

    /** @return array<string,string> */
    private function route(string $method, string $path, string $via): array
    {
        return array('method' => $method, 'path' => $path, 'via' => $via);
    }

    /** @return array<string,mixed> */
    private function link(string $path, string $source): array
    {
        return array('path' => $path, 'source' => $source, 'relative' => false);
    }

    /**
     * @param array<int,array<string,mixed>> $findings
     * @return array<string,mixed>|null the first dangling finding for $id at $path
     */
    private function danglingAt(array $findings, string $id, string $path): ?array
    {
        foreach ($findings as $f) {
            if ($f['check'] === RouteIntegrity::CHECK_DANGLING && $f['a'] === $id && $f['path'] === $path) {
                return $f;
            }
        }

        return null;
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

    // --- synthetic-manifest resolver + collision proofs -------------------------------------

    public function test_true_owns_path_disjoint_methods_do_not_collide(): void
    {
        // Different-family owns_path claims on one path by DISJOINT methods (GET vs POST) co-own
        // legitimately — the phpMyAdmin gate/login shape, proven here without the production fixture.
        $findings = $this->synth(array(
            $this->rec('decoy-a', 'fam-a', array($this->route('GET', '/x', 'owns_path'))),
            $this->rec('decoy-b', 'fam-b', array($this->route('POST', '/x', 'owns_path'))),
        ));
        self::assertSame(array(), $this->only($findings, RouteIntegrity::CHECK_COLLISION, RouteIntegrity::FAIL));
    }

    public function test_overlapping_method_owns_path_produces_one_collision_fail(): void
    {
        // The disjoint control flipped to an overlap (both GET) is a real leak: order alone decides
        // which family serves. Exactly one FAIL naming both ids and the path.
        $findings = $this->synth(array(
            $this->rec('decoy-a', 'fam-a', array($this->route('GET', '/x', 'owns_path'))),
            $this->rec('decoy-b', 'fam-b', array($this->route('GET', '/x', 'owns_path'))),
        ));
        $collisions = $this->only($findings, RouteIntegrity::CHECK_COLLISION, RouteIntegrity::FAIL);
        self::assertCount(1, $collisions);
        self::assertSame('decoy-a', $collisions[0]['a']);
        self::assertSame('decoy-b', $collisions[0]['b']);
        self::assertSame('/x', $collisions[0]['path']);
        self::assertStringContainsString('overlapping method', $collisions[0]['message']);
    }

    public function test_conditional_over_corpus_key_resolves_as_corpus_not_authored(): void
    {
        // A cross-family match-regex claim no longer overrides the exact store: the corpus key at the
        // same path wins (a corpus WARN), never an authored FAIL naming the match-regex owner. This is
        // the runtime-precedence divergence the ticket fixes.
        $findings = $this->synth(
            array(
                $this->rec('decoy-a', 'fam-a', array(), array($this->link('/shared', 'href'))),
                $this->rec('decoy-b', 'fam-b', array($this->route('GET', '/shared', 'match-regex'))),
            ),
            array('GET /shared' => array('family' => 'corpus-fam', 'pid' => 'p1', 'tier' => 'exact-route'))
        );
        self::assertSame(array(), $this->only($findings, RouteIntegrity::CHECK_DANGLING, RouteIntegrity::FAIL));
        $f = $this->danglingAt($findings, 'decoy-a', '/shared');
        self::assertNotNull($f);
        self::assertSame(RouteIntegrity::WARN, $f['severity']);
        self::assertSame('GET /shared', $f['b'], 'winner is the corpus key, not the match-regex owner');
        self::assertStringContainsString('corpus family corpus-fam', $f['message']);
    }

    public function test_conditional_on_store_miss_produces_one_conditional_warn(): void
    {
        // With no exact/corpus/param owner, a fixed-path match-regex claim is surfaced as a conditional
        // candidate WARN — never certified as a serve, because the manifest cannot prove the rule's
        // query/body/header predicate.
        $findings = $this->synth(array(
            $this->rec('decoy-a', 'fam-a', array(), array($this->link('/shared', 'href'))),
            $this->rec('decoy-b', 'fam-b', array($this->route('GET', '/shared', 'match-regex'))),
        ));
        self::assertSame(array(), $this->only($findings, RouteIntegrity::CHECK_DANGLING, RouteIntegrity::FAIL));
        $warns = $this->only($findings, RouteIntegrity::CHECK_DANGLING, RouteIntegrity::WARN);
        self::assertCount(1, $warns);
        self::assertSame('decoy-a', $warns[0]['a']);
        self::assertSame('decoy-b', $warns[0]['b'], 'winner is the match-regex candidate');
        self::assertStringContainsString('conditional match-regex candidate', $warns[0]['message']);
        self::assertStringContainsString('not proven', $warns[0]['message']);
    }

    public function test_same_family_conditional_still_warns_never_certified(): void
    {
        // Even when the match-regex candidate shares the source family, the link is a conditional WARN,
        // not a silent same-family pass: a plain navigation does not submit the field the rule needs.
        $findings = $this->synth(array(
            $this->rec('decoy-a', 'fam-a', array(
                $this->route('POST', '/login.cgi', 'match-regex'),
            ), array($this->link('/login.cgi', 'form-action'))),
        ));
        $f = $this->danglingAt($findings, 'decoy-a', '/login.cgi');
        self::assertNotNull($f);
        self::assertSame(RouteIntegrity::WARN, $f['severity']);
        self::assertStringContainsString('conditional match-regex candidate', $f['message']);
    }

    public function test_true_owns_path_at_corpus_path_still_wins_as_authored_fail(): void
    {
        // The override still precedes the static store: an owns_path claim at a corpus path resolves
        // authored (its family), so a cross-family link there is the existing authored FAIL — proving
        // step 1 was not demoted along with the match-regex demotion.
        $findings = $this->synth(
            array(
                $this->rec('decoy-a', 'fam-a', array(), array($this->link('/shared', 'href'))),
                $this->rec('decoy-b', 'fam-b', array($this->route('GET', '/shared', 'owns_path'))),
            ),
            array('GET /shared' => array('family' => 'corpus-fam', 'pid' => 'p1', 'tier' => 'exact-route'))
        );
        $f = $this->danglingAt($findings, 'decoy-a', '/shared');
        self::assertNotNull($f);
        self::assertSame(RouteIntegrity::FAIL, $f['severity']);
        self::assertSame('decoy-b', $f['b'], 'owns_path owner wins over the corpus key');
        self::assertStringContainsString('different authored family fam-b', $f['message']);
    }

    public function test_dead_unanchored_band_is_removed(): void
    {
        // The resolver never returns an `unanchored` band (a plain self-link carries no attack
        // payload), so the dead FAIL branch and its return-shape entry must not reappear. The bare
        // word survives in the step-5 comment; only the band string literal is asserted gone.
        $src = file_get_contents(self::$root . '/src/Manifest/RouteIntegrity.php');
        self::assertNotFalse($src);
        self::assertStringNotContainsString("'unanchored'", $src);
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
