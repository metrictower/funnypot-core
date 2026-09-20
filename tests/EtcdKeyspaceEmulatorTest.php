<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0390 — unauthenticated etcd keyspace-dump decoy (attack/108-etcd-v2-keyspace.yaml +
 * 109-etcd-v3-range.yaml).
 *
 * Two harnesses:
 *   - The FULL Honeypot over the compiled index proves the load-bearing behaviour: the
 *     108 owns_path OVERRIDE actually fires over the single-template `GET /v2/keys/` store HIT
 *     (rich tree, witness preserved => no coverage loss), and the DROP decision holds — GET /version
 *     is NOT overridden, so its shared-key multi-template corpus serve is intact.
 *   - The TemplateAttackEmulator alone renders the rules in isolation for the branch leaf, the v3
 *     base64 encoding, inertness and the fingerprint-safety seed matrix.
 */
final class EtcdKeyspaceEmulatorTest extends TestCase
{
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    private const ATTACK = __DIR__ . '/../resources/compiled/funnypot-attack.php';

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

    /** A full engine pinned to one persona seed, attack tier live (so classify() runs owns_path). */
    private function engine(string $seed): Honeypot
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
            true,   // attackEmulation => classify() runs the owns_path override
            null,
            null,
            static function (RequestContext $r): bool { return true; },   // probeSignature (root serves)
            '',
            [],
            true
        ));
    }

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::ATTACK, [], 4242);
    }

    // --- (1) the /v2/keys override fires the rich tree and preserves the scanner witness ----------

    public function test_v2_override_fires_rich_tree(): void
    {
        // ?recursive=true is the query, not the path — owns_path claims /v2/keys/ regardless.
        $r = $this->engine('7')->respond(new RequestContext('GET', '/v2/keys/', 'recursive=true', [], null));

        self::assertNotNull($r, 'GET /v2/keys/ must serve');
        self::assertSame(200, $r->status);
        self::assertStringContainsString('application/json', (string) ($r->headers['Content-Type'] ?? ''));
        // Reproduces the corpus scanner witness (bw '"node":','"key":' + '"action":"get"').
        self::assertStringContainsString('"node":', $r->body);
        self::assertStringContainsString('"key":', $r->body);
        self::assertStringContainsString('"action":"get"', $r->body);
        self::assertNotNull(json_decode($r->body, true), 'the served tree must be valid JSON');
        // The OVERRIDE fired (rich tree), not the terse corpus stub.
        self::assertStringContainsString('/registry/secrets', $r->body, 'override must serve the rich keyspace, not the stub');
    }

    // --- (2) no coverage loss: the override supersedes only the single etcd template --------------

    public function test_v2_no_coverage_loss(): void
    {
        $r = $this->engine('7')->respond(new RequestContext('GET', '/v2/keys/', '', [], null));

        self::assertNotNull($r);
        // Single-template route key: the override serves exactly the etcd rule, so witness-preservation
        // == no coverage loss. servedBy confirms the attack tier won over the store bundle.
        self::assertSame('attack-etcd-v2-keyspace', $r->servedBy !== null ? $r->servedBy->ruleId : null);
        self::assertSame(['attack-etcd-v2-keyspace'], $r->satisfies->templateIds());
        self::assertSame(200, $r->status);
        self::assertStringContainsString('"node":', $r->body);
        self::assertStringContainsString('"key":', $r->body);
    }

    // --- (3) leaf subpath serves the single node via the linear scan (not the recursive root) -----

    public function test_v2_leaf_branch(): void
    {
        $path = '/v2/keys/registry/secrets/default/cluster-admin-token';
        $r = $this->emulator()->emulate(new RequestContext('GET', $path, '', [], null), 777);

        self::assertNotNull($r, 'the leaf subpath must resolve via the prefix match, not 404');
        self::assertSame(200, $r->status);
        $j = json_decode($r->body, true);
        self::assertIsArray($j, 'the leaf body must be valid JSON');
        // The etcd node "key" is the etcd keyspace path (no /v2/keys HTTP prefix) — real v2 shape.
        self::assertSame('/registry/secrets/default/cluster-admin-token', $j['node']['key'] ?? null, 'the leaf returns the single requested node');
        self::assertArrayNotHasKey('nodes', $j['node'], 'a leaf read is a single node, not the recursive root');
    }

    // --- (4) v3 /v3/kv/range serves the base64 kvs range response ---------------------------------

    public function test_v3_range_base64(): void
    {
        $body1 = '{"key":"AA==","range_end":"AA=="}';
        $r = $this->emulator()->emulate(new RequestContext('POST', '/v3/kv/range', '', [], $body1), 777);

        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('application/json', (string) ($r->headers['Content-Type'] ?? ''));
        $j = json_decode($r->body, true);
        self::assertIsArray($j);
        self::assertArrayHasKey('kvs', $j);
        self::assertArrayHasKey('count', $j);
        self::assertNotEmpty($j['kvs']);
        // v3 treats keys/values as byte arrays => both must be valid base64.
        self::assertNotFalse(base64_decode((string) $j['kvs'][0]['key'], true), 'kvs[].key must be valid base64');
        self::assertNotFalse(base64_decode((string) $j['kvs'][0]['value'], true), 'kvs[].value must be valid base64');

        // Inert: a DIFFERENT request body yields the SAME canned kvs (response is body-independent).
        $r2 = $this->emulator()->emulate(new RequestContext('POST', '/v3/kv/range', '', [], '{"key":"L2Zvbw=="}'), 777);
        self::assertNotNull($r2);
        self::assertSame($r->body, $r2->body, 'the range response must be independent of the queried key');
    }

    public function test_v3_range_get_also_served(): void
    {
        // Scanners probe /v3/kv/range with GET as well as POST; both must answer.
        $r = $this->emulator()->emulate(new RequestContext('GET', '/v3/kv/range', '', [], null), 777);
        self::assertNotNull($r, 'GET /v3/kv/range must serve');
        self::assertSame(200, $r->status);
        self::assertStringContainsString('"kvs"', $r->body);
    }

    // --- (5) the DROP decision holds: /version is NOT overridden ----------------------------------

    public function test_version_not_regressed(): void
    {
        $sawNonEtcdTemplate = false;
        for ($s = 0; $s < 40; $s++) {
            $r = $this->engine((string) $s)->respond(new RequestContext('GET', '/version', '', [], null));
            self::assertNotNull($r, "GET /version must always serve (seed {$s})");
            $ids = $r->satisfies->templateIds();
            // Never served by this ticket's attack rules — the shared /version key stays with the corpus.
            foreach ($ids as $id) {
                self::assertStringStartsNotWith('attack-etcd', $id, "GET /version must not be an etcd override (seed {$s})");
            }
            foreach ($ids as $id) {
                if (strpos($id, 'etcd') === false) {
                    $sawNonEtcdTemplate = true;
                }
            }
        }
        // The multi-template shared-key serve is intact (a non-etcd /version template still reachable).
        self::assertTrue($sawNonEtcdTemplate, 'the non-etcd /version templates (kube-api/kubernetes/tika/rasa/espec) must survive');
    }

    // --- (6) fingerprint-safe served bytes across a seed matrix -----------------------------------

    public function test_fingerprint_safe(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $probes = [
            ['GET', '/v2/keys/', null],
            ['GET', '/v2/keys/registry/secrets/default/cluster-admin-token', null],
            ['POST', '/v3/kv/range', '{"key":"AA=="}'],
        ];
        for ($seed = 0; $seed <= 15; $seed++) {
            $em = TemplateAttackEmulator::fromFile(self::ATTACK, [], $seed);
            foreach ($probes as [$m, $p, $b]) {
                $r = $em->emulate(new RequestContext($m, $p, '', [], $b), $seed);
                self::assertNotNull($r, "{$m} {$p} must serve at seed {$seed}");
                self::assertSame([], $guard->scan($r->body), "fingerprint leak in {$m} {$p} at seed {$seed}");
            }
        }
    }

    // --- (7) inert: attacker bytes are never reflected --------------------------------------------

    public function test_inert_no_reflection(): void
    {
        $marker = 'ZZ' . 'INJECT' . 'ZZ';
        $r = $this->emulator()->emulate(new RequestContext('POST', '/v3/kv/range', '', [], $marker), 777);
        self::assertNotNull($r);
        self::assertStringNotContainsString($marker, $r->body, 'the request body must never be reflected');
    }
}
