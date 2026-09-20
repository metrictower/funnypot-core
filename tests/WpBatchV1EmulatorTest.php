<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0464 — WordPress Core REST batch-router desync decoy (CVE-2026-63030, attack rule 32).
 *
 * Two trigger surfaces reach the same static 207 Multi-Status envelope through DIFFERENT engine
 * sites, so both are exercised on the real serve path:
 *   - Canonical POST /wp-json/batch/v1 is a store MISS → the linear attack scan (matchRule). Pinned
 *     directly against the compiled attack rules AND end-to-end through Honeypot::respond().
 *   - Query alias POST /?rest_route=/batch/v1 has path `/`, which resolves the homepage entry, so it
 *     can only fire via the classify() owns_path override (owns_path: ['/']). Pinned through the full
 *     engine, the NextjsRscPersonaTest pattern.
 *
 * Also pins the load-bearing invariants: the exact Nettacker predicate
 * (?s)(?=.*block_cannot_read)(?!.*rest_term_invalid), the decline-fallthrough that keeps the
 * homepage safe, and SSRF-no-dispatch (the body never varies with requests[].path).
 */
final class WpBatchV1EmulatorTest extends TestCase
{
    private const ATTACK = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';

    /** The verbatim Nettacker probe body (wordpress_core_cve_2026_63030.yaml). */
    private const PROBE_BODY = '{"validation":"normal","requests":[{"method":"POST","path":"http://:"},{"method":"DELETE","path":"/wp/v2/categories/0"},{"method":"POST","path":"/wp/v2/block-renderer/core/paragraph"}]}';

    /** @var array<string,mixed>|null */
    private static $index;

    /** @return array<string,mixed> */
    private function index(): array
    {
        if (self::$index === null) {
            self::$index = require self::INDEX;
        }

        return self::$index;
    }

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::ATTACK);
    }

    /** A full engine over the compiled index + attack tier, root `/` allowed to serve, gate open. */
    private function engine(string $seed = '0'): Honeypot
    {
        return new Honeypot(new PhpArrayStore($this->index()), new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },   // gate open
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            'realistic',
            'high',
            65536,
            0,
            0,
            true,   // attackEmulation ⇒ classify() runs the owns_path override site
            null,
            null,
            static function (RequestContext $r): bool { return true; },   // probeSignature ⇒ `/` serves
            '',
            [],
            true
        ));
    }

    /** The scanner's exact confirmation predicate: contains block_cannot_read, omits rest_term_invalid. */
    private function assertNettackerPredicate(string $body, string $why): void
    {
        self::assertSame(
            1,
            preg_match('/(?s)(?=.*block_cannot_read)(?!.*rest_term_invalid)/', $body),
            $why . ' must satisfy the Nettacker predicate'
        );
        self::assertStringContainsString('block_cannot_read', $body, $why . ' must carry block_cannot_read');
        self::assertStringNotContainsString('rest_term_invalid', $body, $why . ' must omit rest_term_invalid');
    }

    // --- compile / rule identity ------------------------------------------------------------------

    public function test_rule_compiled_with_owns_root_only(): void
    {
        $rules = require self::ATTACK;
        $ids = array_map(static function (array $r): string { return (string) ($r['id'] ?? ''); }, $rules);
        $rule = null;
        foreach ($rules as $r) {
            if (($r['id'] ?? '') === 'attack-wp-batch-v1') {
                $rule = $r;
                break;
            }
        }
        self::assertNotNull($rule, 'the batch rule must compile');
        self::assertSame(207, (int) $rule['status'], 'status is 207 Multi-Status');
        self::assertSame(['/'], $rule['owns_path'] ?? null, 'owns_path is `/` only (query-alias routing); the canonical path fires via the linear scan');

        // Rules are emitted in priority order; the batch rule (priority 32) must sort BEFORE the broad
        // in:request archetypes, so matchRule() returns it first at the override site (§ priority guard).
        $batchPos = array_search('attack-wp-batch-v1', $ids, true);
        $twigPos = array_search('attack-ssti-twig', $ids, true);
        self::assertIsInt($batchPos);
        self::assertIsInt($twigPos);
        self::assertLessThan($twigPos, $batchPos, 'the batch rule must sort ahead of the broad SSTI archetype');
    }

    // --- canonical surface: linear attack scan ----------------------------------------------------

    public function test_canonical_path_via_direct_emulator_serves_207_witness(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', '/wp-json/batch/v1', '', [], self::PROBE_BODY));
        self::assertNotNull($r, 'the canonical batch probe must serve the decoy');
        self::assertSame(207, $r->status);
        self::assertSame('application/json; charset=UTF-8', $r->headers['Content-Type'] ?? null);
        $this->assertNettackerPredicate($r->body, 'canonical body');
        self::assertSame(['attack-wp-batch-v1'], $r->satisfies->templateIds(), 'the firing rule must be the batch rule, not a broad archetype');
    }

    public function test_canonical_path_end_to_end_through_respond(): void
    {
        // Proves the 207 rides verbatim through respond() → respondAttack() → buildFake() (no clamp).
        $resp = $this->engine()->respond(new RequestContext('POST', '/wp-json/batch/v1', '', [], self::PROBE_BODY));
        self::assertNotNull($resp, 'canonical probe must serve end-to-end');
        self::assertSame(207, $resp->status, '207 must survive the full serve path');
        self::assertSame('application/json; charset=UTF-8', $resp->headers['Content-Type'] ?? null);
        $this->assertNettackerPredicate($resp->body, 'canonical end-to-end body');
    }

    // --- query-alias surface: owns_path override site ---------------------------------------------

    public function test_query_alias_via_owns_root_override_serves_207_witness(): void
    {
        // Path is `/`; only owns_path: ['/'] routes this into the override site. If the owns-`/` claim
        // or the top-level decline gate were wrong, this would return the homepage 200 instead.
        $resp = $this->engine()->respond(new RequestContext('POST', '/', 'rest_route=/batch/v1', [], self::PROBE_BODY));
        self::assertNotNull($resp, 'the query-alias probe must serve the decoy');
        self::assertSame(207, $resp->status, 'query alias must reach the 207 via the owns_path override');
        self::assertSame('application/json; charset=UTF-8', $resp->headers['Content-Type'] ?? null);
        $this->assertNettackerPredicate($resp->body, 'query-alias body');
    }

    // --- decline-fallthrough: owns-`/` must not eat the homepage ----------------------------------

    public function test_plain_post_root_declines_to_homepage_not_207(): void
    {
        // A non-batch POST / must NOT match the batch rule (no batch token, no "requests"). The rule
        // declines at the top-level match; the root-entry exemption keeps the homepage serving.
        $resp = $this->engine()->respond(new RequestContext('POST', '/', '', [], '{"hello":"world"}'));
        if ($resp !== null) {
            self::assertNotSame(207, $resp->status, 'a plain POST / must never serve the batch 207');
            self::assertStringNotContainsString('block_cannot_read', $resp->body, 'a plain POST / must not leak the batch witness');
        }
        self::assertTrue(true);
    }

    public function test_plain_get_root_serves_homepage_not_207(): void
    {
        $resp = $this->engine()->respond(new RequestContext('GET', '/'));
        self::assertNotNull($resp, 'plain GET / must still serve a homepage');
        self::assertSame(200, $resp->status, 'GET / is the ordinary homepage, unchanged');
        self::assertStringNotContainsString('block_cannot_read', $resp->body, 'the homepage must not carry the batch witness');
    }

    // --- verb gate: GET on the canonical path falls through ---------------------------------------

    public function test_get_on_canonical_path_is_not_the_207_decoy(): void
    {
        // The ^POST$ method clause declines GET; the batch rule must not fire for GET /wp-json/batch/v1.
        $r = $this->emulator()->emulate(new RequestContext('GET', '/wp-json/batch/v1', '', [], self::PROBE_BODY));
        if ($r !== null) {
            self::assertNotSame(['attack-wp-batch-v1'], $r->satisfies->templateIds(), 'GET must not fire the batch rule');
        }
        self::assertTrue(true);
    }

    // --- SSRF-no-dispatch: the body never varies with requests[].path -----------------------------

    public function test_no_dispatch_response_is_identical_across_payloads(): void
    {
        // Two batch bodies whose requests[].path differ wildly (SSRF-shaped vs internal) must yield a
        // byte-identical envelope — proving no sub-request is parsed, dispatched, or reflected.
        $a = '{"requests":[{"method":"POST","path":"http://:"},{"method":"GET","path":"/wp/v2/users/1"}]}';
        $b = '{"requests":[{"method":"DELETE","path":"http://169.254.169.254/latest/meta-data/"},{"method":"POST","path":"/wp/v2/block-renderer/core/paragraph"}]}';

        $ra = $this->emulator()->emulate(new RequestContext('POST', '/wp-json/batch/v1', '', [], $a));
        $rb = $this->emulator()->emulate(new RequestContext('POST', '/wp-json/batch/v1', '', [], $b));

        self::assertNotNull($ra);
        self::assertNotNull($rb);
        self::assertSame($ra->body, $rb->body, 'the envelope must not depend on requests[].path');
        self::assertStringNotContainsString('169.254.169.254', $ra->body, 'no attacker path is reflected');
        self::assertStringNotContainsString('block-renderer', $rb->body, 'no attacker path is reflected');
    }
}
