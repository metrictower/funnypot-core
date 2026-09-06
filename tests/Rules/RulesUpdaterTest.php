<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Rules;

use Funnypot\Core\Rules\KeyRing;
use Funnypot\Core\Rules\RulesLocator;
use Funnypot\Core\Rules\RulesUpdater;
use Funnypot\Core\Rules\SignatureVerifier;
use Funnypot\Core\SchemaVersion;
use Funnypot\Core\Tests\Support\ArrayFetcher;
use Funnypot\Core\Tests\Support\ReleaseFactory;
use PHPUnit\Framework\TestCase;

/**
 * The end-to-end trust + swap + fail-safe contract. Every negative test also asserts the
 * load-bearing property: on ANY failure, `current` is untouched — the engine keeps serving
 * the prior release (or the bundled floor), never empty.
 */
final class RulesUpdaterTest extends TestCase
{
    /** @var string */
    private $tmp;

    /** @var ArrayFetcher */
    private $fetcher;

    /** @var ReleaseFactory */
    private $factory;

    protected function setUp(): void
    {
        RulesLocator::reset();
        $this->tmp = sys_get_temp_dir() . '/funnypot-updater-' . bin2hex(random_bytes(6));
        mkdir($this->tmp, 0755, true);
        $this->fetcher = new ArrayFetcher();
        $this->factory = new ReleaseFactory($this->tmp . '/build');
    }

    protected function tearDown(): void
    {
        RulesLocator::reset();
        $this->rmrf($this->tmp);
    }

    private function dataDir(): string
    {
        return $this->tmp . '/data';
    }

    /** An updater pinned to $version, trusting only the factory key, low first-install floor. */
    private function updater(string $version, ?SignatureVerifier $verifier = null): RulesUpdater
    {
        $u = new RulesUpdater(
            $this->dataDir(),
            'stable',
            $version,
            $this->factory->baseUrl,
            $this->fetcher,
            $verifier ?? $this->factory->verifier()
        );
        $u->setPackagedCoverageForTesting(['routes' => 1, 'templates' => 1, 'attack_rules' => 1]);

        return $u;
    }

    private function currentTarget(): ?string
    {
        $link = $this->dataDir() . '/current';

        return is_link($link) ? readlink($link) : null;
    }

    public function test_update_installs_verifies_and_activates(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(100, 100));

        $result = $this->updater('v1')->update();

        self::assertTrue($result->success, $result->message);
        self::assertTrue($result->changed);
        self::assertSame('v1', $result->toVersion);

        // current resolves and RulesLocator prefers it.
        RulesLocator::useDataDir($this->dataDir());
        $resolved = RulesLocator::resolve('nuclei-index.full.php');
        self::assertSame($this->dataDir() . '/current/nuclei-index.full.php', $resolved);
        self::assertTrue(is_file($resolved));

        $status = $this->updater('v1')->status();
        self::assertSame('v1', $status->version);
        self::assertSame('data-dir', $status->source);
        self::assertSame(100, $status->coverage['routes']);
    }

    public function test_rejects_and_never_executes_an_unlisted_php_in_the_tarball(): void
    {
        // The unlisted-file RCE: a malicious engine/funnypot-attack.php that the (attacker-authored)
        // manifest omits from `files`. Validating only listed files would leave it unvalidated, then
        // runSafetySubset() require()s it -> code exec. The on-disk tree walk must reject it first.
        $marker = $this->tmp . '/rce-marker';
        $engine = $this->factory->engineFiles(100, 100);
        $engine['funnypot-attack.php'] = '<?php file_put_contents(' . var_export($marker, true) . ", 'x'); return [];\n";
        $files = [];
        foreach ($engine as $name => $contents) {
            if ($name !== 'funnypot-attack.php') {
                $files['engine/' . $name] = hash('sha256', $contents);
            }
        }
        $this->factory->publish($this->fetcher, 'v1', 1, $engine, ['files' => $files]);

        $result = $this->updater('v1')->update();

        self::assertFalse($result->success, 'an unlisted file must fail the update');
        self::assertFileDoesNotExist($marker, "the unlisted malicious artifact must never be require'd");
        self::assertNull($this->currentTarget(), 'a rejected update must not activate anything');
    }

    public function test_second_run_at_same_version_is_a_noop(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $this->updater('v1')->update();

        $result = $this->updater('v1')->update();
        self::assertTrue($result->success);
        self::assertFalse($result->changed);
        self::assertSame('already-current', $result->status);
    }

    public function test_tampered_artifact_fails_sha256_and_keeps_current(): void
    {
        // Install a good v1 first.
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $this->updater('v1')->update();
        $before = $this->currentTarget();

        // Publish v2, then overwrite its tarball with bytes that no longer match the signed sha.
        $this->factory->publish($this->fetcher, 'v2', 2, $this->factory->engineFiles());
        $this->factory->tamper($this->fetcher, 'v2', 'funnypot-rules-v2.tar.gz', 'corrupted-bytes');

        $result = $this->updater('v2')->update();
        self::assertFalse($result->success);
        self::assertSame('sha256-mismatch', $result->status);
        self::assertSame($before, $this->currentTarget(), 'current must still point at v1');
        self::assertSame('v1', $this->updater('v2')->status()->version);
    }

    public function test_tampered_manifest_fails_signature_and_keeps_current(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $this->updater('v1')->update();
        $before = $this->currentTarget();

        $pub = $this->factory->publish($this->fetcher, 'v2', 2, $this->factory->engineFiles());
        // Flip a byte in the manifest AFTER it was signed → signature no longer verifies.
        $badManifest = str_replace('"version_seq":2', '"version_seq":9', json_encode($pub['manifest'], JSON_UNESCAPED_SLASHES));
        $this->factory->tamper($this->fetcher, 'v2', 'v2.manifest.json', $badManifest);

        $result = $this->updater('v2')->update();
        self::assertFalse($result->success);
        self::assertSame('bad-signature', $result->status);
        self::assertSame($before, $this->currentTarget());
    }

    public function test_poisoned_php_is_rejected_even_with_a_valid_signature(): void
    {
        // A COMPROMISED-but-trusted signer ships a non-literal artifact, correctly signed and
        // hashed. The PhpLiteralValidator gate must still refuse it before it is ever require'd.
        $files = $this->factory->engineFiles();
        $files['funnypot-attack.php'] = "<?php system('id'); return [];";
        $this->factory->publish($this->fetcher, 'v1', 1, $files);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('not-literal', $result->status);
        self::assertNull($this->currentTarget(), 'nothing should be activated');
    }

    public function test_fingerprint_leak_is_rejected(): void
    {
        $rules = [[
            'id' => 'attack-leak',
            'match' => [['in' => 'query', 'contains' => 'x']],
            'response' => ['body' => 'blocked by OWASP_CRS ruleset'],
        ]];
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(100, 100, $rules));

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('fingerprint-leak', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_behavior_primitive_served_shape_fingerprint_leak_is_rejected(): void
    {
        // arith-eval serves its own `response`, and iterate serves wrap.open/close + the per-sub-call
        // `item` — nested served shapes that never reach the top-level body. servedTexts() descends
        // into each, so a detector signature planted there (top-level body kept clean) must fail the
        // update before activation, proving the descent ran fetch-time.
        $leakyRules = [
            'arith-eval.response' => [[
                'id' => 'attack-arith-leak',
                'match' => [['in' => 'query', 'contains' => 'x']],
                'response' => ['headers' => [], 'body' => 'clean top-level'],
                'behavior' => 'arith-eval',
                'arith-eval' => [
                    'left' => 'a', 'right' => 'b', 'op' => 'add',
                    'response' => ['headers' => [], 'body' => 'blocked by OWASP_CRS ruleset'],
                ],
            ]],
            'iterate.wrap' => [[
                'id' => 'attack-iterate-leak',
                'match' => [['in' => 'query', 'contains' => 'x']],
                'response' => ['headers' => [], 'body' => 'clean top-level'],
                'behavior' => 'iterate',
                'iterate' => [
                    'parse' => 'xmlrpc-multicall', 'max_items' => 8,
                    'wrap' => ['open' => 'detected via libinjection', 'close' => '</r>'],
                    'item' => ['headers' => [], 'body' => '<m/>'],
                ],
            ]],
            // iterate.response.headers is served on the multicall success path — a nested node the
            // top-level body never carries. servedTexts() must descend into it so a leak there is
            // rejected fetch-time; top-level body + wrap + item stay clean, so a catch proves it.
            'iterate.response' => [[
                'id' => 'attack-iterate-response-leak',
                'match' => [['in' => 'query', 'contains' => 'x']],
                'response' => ['headers' => [], 'body' => 'clean top-level'],
                'behavior' => 'iterate',
                'iterate' => [
                    'parse' => 'xmlrpc-multicall', 'max_items' => 8,
                    'wrap' => ['open' => '<r>', 'close' => '</r>'],
                    'item' => ['headers' => [], 'body' => '<m/>'],
                    'response' => ['headers' => ['X-Powered-By' => 'OWASP_CRS/3.3.0'], 'body' => ''],
                ],
            ]],
        ];

        $seq = 1;
        foreach ($leakyRules as $shape => $rules) {
            $version = 'v' . $seq;
            $this->factory->publish($this->fetcher, $version, $seq, $this->factory->engineFiles(100, 100, $rules));

            $result = $this->updater($version)->update();
            self::assertFalse($result->success, "{$shape} leak must fail the update");
            self::assertSame('fingerprint-leak', $result->status, "{$shape} leak");
            self::assertNull($this->currentTarget(), "{$shape} leak must not activate anything");
            $seq++;
        }
    }

    public function test_route_rule_fingerprint_leak_is_rejected(): void
    {
        // The installed engine serves ROUTE responses too, so runSafetySubset() re-scans the route
        // artifact with the same dual-shape + set_cookie + taunt extraction as the attack surface. A
        // detector signature anywhere an attacker can see it — body, a Set-Cookie name, a taunt
        // comment — must fail the update before activation, never leak out on a served route.
        $leakyRoutes = [
            'body' => [['id' => 'route-x', 'match' => ['pid' => ['p']], 'body' => 'blocked by OWASP_CRS ruleset', 'headers' => []]],
            'set_cookie' => [['id' => 'route-x', 'match' => ['pid' => ['p']], 'body' => 'ok', 'headers' => [], 'set_cookie' => 'modsecurity_session']],
            'taunt.open' => [['id' => 'route-x', 'match' => ['pid' => ['p']], 'body' => 'ok', 'headers' => [], 'taunt' => ['mode' => 'line', 'open' => '# OWASP_CRS']]],
        ];

        $seq = 1;
        foreach ($leakyRoutes as $surface => $routes) {
            $version = 'v' . $seq;
            $engine = $this->factory->engineFiles(100, 100);
            $engine['funnypot-routes.php'] = $this->factory->literal($routes);
            $this->factory->publish($this->fetcher, $version, $seq, $engine);

            $result = $this->updater($version)->update();
            self::assertFalse($result->success, "route {$surface} leak must fail the update");
            self::assertSame('fingerprint-leak', $result->status, "route {$surface} leak");
            self::assertNull($this->currentTarget(), "route {$surface} leak must not activate anything");
            $seq++;
        }
    }

    public function test_non_array_route_artifact_is_rejected(): void
    {
        // A route artifact whose literal is not a top-level array can't be scanned rule-by-rule;
        // runSafetySubset() must reject it as a bad manifest, never skip the re-scan and swap it in.
        $engine = $this->factory->engineFiles(100, 100);
        $engine['funnypot-routes.php'] = $this->factory->literal('not-an-array');
        $this->factory->publish($this->fetcher, 'v1', 1, $engine);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('bad-manifest', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_param_traversal_read_fingerprint_leak_is_rejected(): void
    {
        // The installed engine serves PARAM responses too, including a traversal-read allow body —
        // a synthesized file under a nested key. runSafetySubset() flattens the param buckets and
        // descends into traversal-read content, so a detector signature there must fail the update
        // before activation. The top-level response stays clean, so a catch proves the descent ran.
        $engine = $this->factory->engineFiles(100, 100);
        $engine['funnypot-param.php'] = $this->factory->literal([
            'schema' => 1,
            'buckets' => [
                '@fs' => [
                    [
                        'id' => 'param-leak',
                        'severity' => 'high',
                        'tags' => [],
                        'status' => 404,
                        'method' => 'GET',
                        'regex' => '^/@fs/(?P<path>.+)$',
                        'captures' => ['path'],
                        'response' => ['headers' => [], 'body' => 'clean not found'],
                        'behavior' => 'traversal-read',
                        'traversal-read' => [
                            'allow' => [
                                ['suffix' => '.env', 'content' => ['headers' => [], 'body' => 'blocked by OWASP_CRS ruleset', 'status' => 200]],
                            ],
                        ],
                    ],
                ],
            ],
        ]);
        $this->factory->publish($this->fetcher, 'v1', 1, $engine);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('fingerprint-leak', $result->status);
        self::assertNull($this->currentTarget(), 'a param traversal-read leak must not activate anything');
    }

    public function test_ssti_render_served_leak_is_rejected(): void
    {
        // ssti-render serves its own nested `response`. The old hand-mirrored rescan walker never
        // descended it (it was in the CI gate but not the updater — a drift), so a leak there could
        // ride a fetched release. The shared ServedStringWalker descends it, closing the drift.
        $rules = [[
            'id' => 'attack-ssti-leak',
            'match' => [['in' => 'query', 'contains' => 'x']],
            'response' => ['headers' => [], 'body' => 'clean top-level'],
            'behavior' => 'ssti-render',
            'ssti-render' => [
                'surface' => 'surface', 'bind' => 'rendered',
                'response' => ['headers' => [], 'body' => 'blocked by OWASP_CRS ruleset'],
            ],
        ]];
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(100, 100, $rules));

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('fingerprint-leak', $result->status);
        self::assertNull($this->currentTarget(), 'an ssti-render served leak must not activate anything');
    }

    public function test_nuclei_index_bundle_fingerprint_leak_is_rejected(): void
    {
        // The installed engine serves the nuclei index's bw/hw/th witnesses verbatim, so the rescan
        // now covers the index too (FP-0262). A detector signature in a served bundle word must fail
        // the update before activation.
        $engine = $this->factory->engineFiles(100, 100);
        $engine['nuclei-index.full.php'] = $this->factory->literal([
            'schema' => 1,
            'manifest' => ['schema' => 1],
            'routes' => ['GET /leak' => ['b' => [['pid' => 'p', 't' => ['t'], 'bw' => ['blocked by OWASP_CRS ruleset']]]]],
            'templates' => [],
        ]);
        $this->factory->publish($this->fetcher, 'v1', 1, $engine);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('fingerprint-leak', $result->status);
        self::assertNull($this->currentTarget(), 'a nuclei-index leak must not activate anything');
    }

    public function test_flat_routes_index_fingerprint_leak_is_rejected(): void
    {
        // The flat routes-index (folded new-page bundles) is served too; the rescan covers its FLAT
        // bundle shape. A typed-header OAST domain there must fail the update before activation.
        $engine = $this->factory->engineFiles(100, 100);
        $engine['funnypot-routes-index.php'] = $this->factory->literal([
            'routes' => ['GET /leak' => [['pid' => 'p', 't' => ['t'], 'th' => ['Location' => ['https://oast.pro']]]]],
            'templates' => [],
        ]);
        $this->factory->publish($this->fetcher, 'v1', 1, $engine);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('fingerprint-leak', $result->status);
        self::assertNull($this->currentTarget(), 'a flat routes-index leak must not activate anything');
    }

    public function test_non_array_param_artifact_is_rejected(): void
    {
        // A param artifact whose literal is not a top-level array can't be flattened + scanned;
        // runSafetySubset() must reject it as a bad manifest, never skip the re-scan and swap it in.
        $engine = $this->factory->engineFiles(100, 100);
        $engine['funnypot-param.php'] = $this->factory->literal('not-an-array');
        $this->factory->publish($this->fetcher, 'v1', 1, $engine);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('bad-manifest', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_missing_param_artifact_is_rejected(): void
    {
        // funnypot-param.php is a required engine artifact; a release that omits it is incomplete
        // and must fail before activation (never swap in a set the engine can't fully load).
        $engine = $this->factory->engineFiles(100, 100);
        unset($engine['funnypot-param.php']);
        $this->factory->publish($this->fetcher, 'v1', 1, $engine);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('bad-manifest', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_catastrophic_regex_is_rejected(): void
    {
        $rules = [[
            'id' => 'attack-redos',
            'match' => [['in' => 'query', 'regex' => '(a+)+$']],
            'response' => ['body' => 'ok'],
        ]];
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(100, 100, $rules));

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('redos', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_anti_blinding_floor_rejects_a_coverage_drop(): void
    {
        // Good v1 with 100 routes.
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(100, 100));
        $this->updater('v1')->update();
        $before = $this->currentTarget();

        // v2 guts coverage to 1 route — a silent detection-kill, not an update.
        $this->factory->publish($this->fetcher, 'v2', 2, $this->factory->engineFiles(1, 1));
        $result = $this->updater('v2')->update();

        self::assertFalse($result->success);
        self::assertSame('coverage-drop', $result->status);
        self::assertSame($before, $this->currentTarget());
        self::assertSame('v1', $this->updater('v2')->status()->version);
    }

    public function test_anti_downgrade_refuses_an_older_sequence(): void
    {
        $this->factory->publish($this->fetcher, 'v2', 2, $this->factory->engineFiles());
        $this->updater('v2')->update();

        // An attacker replays a validly-signed older release (seq 1).
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $result = $this->updater('v1')->update();

        self::assertFalse($result->success);
        self::assertSame('downgrade', $result->status);
        self::assertSame('v2', $this->updater('v2')->status()->version);
    }

    public function test_a_newer_manifest_schema_is_refused_and_keeps_current(): void
    {
        // Good v1 first, on the schema this engine understands.
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $this->updater('v1')->update();
        $before = $this->currentTarget();

        // v2's manifest declares a schema ahead of SchemaVersion::RELEASE_CURRENT — an older deployed
        // engine must refuse it rather than mis-parse a newer release format.
        $this->factory->publish($this->fetcher, 'v2', 2, $this->factory->engineFiles(), ['schema' => SchemaVersion::RELEASE_CURRENT + 1]);
        $result = $this->updater('v2')->update();

        self::assertFalse($result->success);
        self::assertSame('schema-too-new', $result->status);
        self::assertSame($before, $this->currentTarget(), 'current must still point at v1');
        self::assertSame('v1', $this->updater('v2')->status()->version);
    }

    public function test_rollback_repoints_to_a_retained_release(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(100, 100));
        $this->updater('v1')->update();
        $this->factory->publish($this->fetcher, 'v2', 2, $this->factory->engineFiles(120, 120));
        $this->updater('v2')->update();
        self::assertSame('v2', $this->updater('v2')->status()->version);

        // Network-free rollback to the previous retained release.
        $result = $this->updater('v2')->rollback();
        self::assertTrue($result->success, $result->message);
        self::assertSame('rolled-back', $result->status);
        self::assertSame('v1', $result->toVersion);
        self::assertSame('v1', $this->updater('v2')->status()->version);
    }

    public function test_empty_keyring_fails_closed(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $verifier = new SignatureVerifier(new KeyRing([])); // trusts nobody
        $result = $this->updater('v1', $verifier)->update();

        self::assertFalse($result->success);
        self::assertSame('no-trusted-key', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_channel_resolution_via_signed_channels_json(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $this->factory->publishChannels($this->fetcher, ['stable' => 'v1', 'latest' => 'v1', 'revoked' => []]);

        // No pinned version — resolve through the signed channels pointer.
        $u = new RulesUpdater($this->dataDir(), 'stable', null, $this->factory->baseUrl, $this->fetcher, $this->factory->verifier());
        $u->setPackagedCoverageForTesting(['routes' => 1, 'templates' => 1, 'attack_rules' => 1]);
        $result = $u->update();

        self::assertTrue($result->success, $result->message);
        self::assertSame('v1', $result->toVersion);
    }

    public function test_concurrent_run_is_a_benign_noop(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        // Hold the lock as if another process were mid-update.
        mkdir($this->dataDir(), 0755, true);
        $held = fopen($this->dataDir() . '/.lock', 'c');
        self::assertNotFalse($held);
        flock($held, LOCK_EX);

        $result = $this->updater('v1')->update();
        self::assertTrue($result->success);
        self::assertFalse($result->changed);
        self::assertSame('busy', $result->status);

        flock($held, LOCK_UN);
        fclose($held);
    }

    // ------------------------------------------------------------ F1: freshness / replay

    public function test_replayed_expired_channels_metadata_is_rejected_as_stale(): void
    {
        // The named replay-old-metadata test: an old-but-validly-signed channels.json whose window
        // has lapsed. Fail-safe to last-good (nothing was installed), reason distinctly stale.
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $this->factory->publishChannels(
            $this->fetcher,
            ['stable' => 'v1', 'revoked' => []],
            ['generated_at' => gmdate('c', 1000), 'expires' => gmdate('c', 2000)]
        );

        $u = new RulesUpdater($this->dataDir(), 'stable', null, $this->factory->baseUrl, $this->fetcher, $this->factory->verifier());
        $u->setPackagedCoverageForTesting(['routes' => 1, 'templates' => 1, 'attack_rules' => 1]);
        $u->setNowForTesting(1_000_000_000); // long after `expires`
        $result = $u->update();

        self::assertFalse($result->success);
        self::assertSame('stale-metadata', $result->status);
        self::assertNull($this->currentTarget(), 'a stale pointer must not activate anything');
    }

    public function test_replayed_channels_freeze_does_not_refresh_checked_at(): void
    {
        // Install a good v1 through the channel (checked_at now set).
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $this->factory->publishChannels($this->fetcher, ['stable' => 'v1', 'revoked' => []]);
        $u = new RulesUpdater($this->dataDir(), 'stable', null, $this->factory->baseUrl, $this->fetcher, $this->factory->verifier());
        $u->setPackagedCoverageForTesting(['routes' => 1, 'templates' => 1, 'attack_rules' => 1]);
        $u->update();
        $checkedBefore = $u->status()->checkedAt;
        self::assertNotNull($checkedBefore);

        // The freeze attack: replay an EXPIRED channels.json still pointing at the installed v1. The
        // old no-op path would refresh checked_at (silencing the staleness alarm); now the stale
        // pointer is rejected BEFORE the no-op, so checked_at must NOT advance.
        $this->factory->publishChannels(
            $this->fetcher,
            ['stable' => 'v1', 'revoked' => []],
            ['generated_at' => gmdate('c', 1000), 'expires' => gmdate('c', 2000)]
        );
        $u2 = new RulesUpdater($this->dataDir(), 'stable', null, $this->factory->baseUrl, $this->fetcher, $this->factory->verifier());
        $u2->setPackagedCoverageForTesting(['routes' => 1, 'templates' => 1, 'attack_rules' => 1]);
        $u2->setNowForTesting(1_000_000_000);
        $result = $u2->update();

        self::assertFalse($result->success);
        self::assertSame('stale-metadata', $result->status);
        self::assertSame($checkedBefore, $u2->status()->checkedAt, 'a frozen channel must not refresh checked_at');
    }

    public function test_expired_manifest_is_rejected_even_when_pinned(): void
    {
        // A pinned install skips channels but still enforces the manifest's own freshness window.
        $this->factory->publish(
            $this->fetcher,
            'v1',
            1,
            $this->factory->engineFiles(),
            ['generated_at' => gmdate('c', 1000), 'expires' => gmdate('c', 2000)]
        );
        $u = $this->updater('v1');
        $u->setNowForTesting(1_000_000_000);
        $result = $u->update();

        self::assertFalse($result->success);
        self::assertSame('stale-metadata', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_freshness_tolerates_clock_skew(): void
    {
        // A manifest that expired 200 s ago is still accepted inside the 300 s skew tolerance.
        $now = 1_000_000_000;
        $this->factory->publish(
            $this->fetcher,
            'v1',
            1,
            $this->factory->engineFiles(),
            ['generated_at' => gmdate('c', $now - 3600), 'expires' => gmdate('c', $now - 200)]
        );
        $u = $this->updater('v1');
        $u->setNowForTesting($now);
        $result = $u->update();

        self::assertTrue($result->success, $result->message);
        self::assertSame('v1', $result->toVersion);
    }

    public function test_far_future_generated_at_is_rejected(): void
    {
        // generated_at well beyond now + skew is a broken publisher clock or a skew attack.
        $now = 1_000_000_000;
        $this->factory->publish(
            $this->fetcher,
            'v1',
            1,
            $this->factory->engineFiles(),
            ['generated_at' => gmdate('c', $now + 4000), 'expires' => gmdate('c', $now + 90 * 86400)]
        );
        $u = $this->updater('v1');
        $u->setNowForTesting($now);
        $result = $u->update();

        self::assertFalse($result->success);
        self::assertSame('stale-metadata', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_missing_freshness_fields_on_schema2_are_rejected(): void
    {
        // A schema-2 manifest that omits the window is a broken/forged envelope — freshness is not
        // optional once the format carries it. (unset via override to null-out the defaults.)
        $pub = $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $manifest = $pub['manifest'];
        unset($manifest['generated_at'], $manifest['expires']);
        // Re-sign the trimmed manifest so it fails on freshness, not signature.
        $bytes = json_encode($manifest, JSON_UNESCAPED_SLASHES);
        $sig = $this->factory->sign(SignatureVerifier::CONTEXT_MANIFEST, $bytes, 'release');
        $this->factory->tamper($this->fetcher, 'v1', 'v1.manifest.json', $bytes);
        $this->factory->tamper($this->fetcher, 'v1', 'v1.manifest.json.sig', $sig);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('bad-manifest', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_channel_generated_at_is_persisted_and_exposed(): void
    {
        $now = 1_000_000_000;
        $genAt = gmdate('c', $now - 3600);
        $this->factory->publish(
            $this->fetcher,
            'v1',
            1,
            $this->factory->engineFiles(),
            ['generated_at' => gmdate('c', $now - 3600), 'expires' => gmdate('c', $now + 90 * 86400)]
        );
        $this->factory->publishChannels(
            $this->fetcher,
            ['stable' => 'v1', 'revoked' => []],
            ['generated_at' => $genAt, 'expires' => gmdate('c', $now + 7 * 86400)]
        );
        $u = new RulesUpdater($this->dataDir(), 'stable', null, $this->factory->baseUrl, $this->fetcher, $this->factory->verifier());
        $u->setPackagedCoverageForTesting(['routes' => 1, 'templates' => 1, 'attack_rules' => 1]);
        $u->setNowForTesting($now);
        $u->update();

        $status = $u->status();
        self::assertSame($genAt, $status->channelGeneratedAt);
        self::assertSame($genAt, $status->toArray()['channel_generated_at']);
    }

    // ------------------------------------------------------------ F3: decompression bomb

    public function test_forged_isize_gzip_bomb_is_rejected_before_extraction(): void
    {
        // The named forged-ISIZE bomb test. A tarball that decompresses to 2 MiB with an ISIZE forged
        // to 1024 bytes; the streaming counter (cap shrunk to 512 KiB) catches it despite the trailer.
        $this->factory->publishBomb($this->fetcher, 'v1', 1, 2 * 1024 * 1024);
        $u = $this->updater('v1');
        $u->setMaxExtractedBytesForTesting(512 * 1024);
        $result = $u->update();

        self::assertFalse($result->success);
        self::assertSame('extract-failed', $result->status);
        self::assertNull($this->currentTarget());

        // No partial dir survives, and no ~bomb-size file was left anywhere under the data dir.
        foreach (scandir($this->dataDir()) ?: [] as $item) {
            self::assertStringStartsNotWith('.partial-', $item, 'the partial extraction dir must be cleaned up');
        }
        self::assertSame(0, $this->largestFileUnder($this->dataDir(), 512 * 1024), 'no oversized file may be left on disk');
    }

    public function test_truncated_gzip_stream_is_rejected(): void
    {
        $this->factory->publishTruncatedGzip($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $result = $this->updater('v1')->update();

        self::assertFalse($result->success);
        self::assertSame('extract-failed', $result->status);
        self::assertNull($this->currentTarget());
    }

    // ------------------------------------------------------------ F4: domain + role separation

    public function test_channels_signed_by_release_key_is_rejected(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        // channels.json signed (with the channels context) by the RELEASE key — no channels-role key
        // can verify it.
        $this->factory->publishChannels($this->fetcher, ['stable' => 'v1', 'revoked' => []], [], null, 'release');
        $u = new RulesUpdater($this->dataDir(), 'stable', null, $this->factory->baseUrl, $this->fetcher, $this->factory->verifier());
        $u->setPackagedCoverageForTesting(['routes' => 1, 'templates' => 1, 'attack_rules' => 1]);
        $result = $u->update();

        self::assertFalse($result->success);
        self::assertSame('bad-signature', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_manifest_signed_by_channels_key_is_rejected(): void
    {
        // Manifest signed (with the manifest context) by the CHANNELS key — no release-role key verifies.
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(), [], null, 'channels');
        $result = $this->updater('v1')->update();

        self::assertFalse($result->success);
        self::assertSame('bad-signature', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_legacy_context_free_schema1_manifest_fails_under_context_verifier(): void
    {
        // A pre-hardening schema-1 manifest signed over RAW bytes (no context prefix) by the release
        // key. Under the context-prefixed verifier it can never verify — the correct fail-closed
        // outcome, since the shipped ring is empty and there is NO legacy verification path.
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(), ['schema' => 1], '');
        $result = $this->updater('v1')->update();

        self::assertFalse($result->success);
        self::assertSame('bad-signature', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_channels_bytes_cannot_replay_as_manifest(): void
    {
        // Domain separation: take a validly channels-signed document and serve it (bytes + its own
        // sig) at the manifest URL. The manifest verifier prefixes CONTEXT_MANIFEST, so the
        // channels-context signature cannot verify.
        $this->factory->publishChannels($this->fetcher, ['stable' => 'v9', 'revoked' => []]);
        $channelsBytes = $this->fetcher->get($this->factory->channelsUrl('channels.json'));
        $channelsSig = $this->fetcher->get($this->factory->channelsUrl('channels.json.sig'));
        $this->fetcher->put($this->factory->assetUrl('v9', 'v9.manifest.json'), $channelsBytes);
        $this->fetcher->put($this->factory->assetUrl('v9', 'v9.manifest.json.sig'), $channelsSig);

        $result = $this->updater('v9')->update();
        self::assertFalse($result->success);
        self::assertSame('bad-signature', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_newer_channels_schema_is_refused(): void
    {
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles());
        $this->factory->publishChannels($this->fetcher, ['stable' => 'v1', 'revoked' => []], ['schema' => SchemaVersion::RELEASE_CURRENT + 1]);
        $u = new RulesUpdater($this->dataDir(), 'stable', null, $this->factory->baseUrl, $this->fetcher, $this->factory->verifier());
        $u->setPackagedCoverageForTesting(['routes' => 1, 'templates' => 1, 'attack_rules' => 1]);
        $result = $u->update();

        self::assertFalse($result->success);
        self::assertSame('schema-too-new', $result->status);
        self::assertNull($this->currentTarget());
    }

    // ------------------------------------------------------------ F5: widened ReDoS screen

    public function test_param_bucket_catastrophic_regex_is_rejected(): void
    {
        // A param-bucket entry regex runs on attacker path bytes at runtime (matchParamRoute) but was
        // NOT screened before this ticket. The widened walk must catch a catastrophic pattern there.
        $engine = $this->factory->engineFiles(100, 100);
        $engine['funnypot-param.php'] = $this->factory->literal([
            'schema' => 1,
            'buckets' => [
                '@fs' => [[
                    'id' => 'param-redos',
                    'severity' => 'high',
                    'tags' => [],
                    'status' => 200,
                    'method' => 'GET',
                    'regex' => '(a+)+$',
                    'captures' => [],
                    'response' => ['headers' => [], 'body' => 'ok'],
                ]],
            ],
        ]);
        $this->factory->publish($this->fetcher, 'v1', 1, $engine);

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('redos', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_branch_when_catastrophic_regex_is_rejected(): void
    {
        // A nested branch case `when.regex` runs on attacker bytes via evalConditions but was NOT
        // screened before this ticket (only top-level match[].regex was). It must now fail the update.
        $rules = [[
            'id' => 'attack-branch-redos',
            'match' => [['in' => 'query', 'regex' => 'q=([a-z]+)']],
            'response' => ['body' => 'ok'],
            'behavior' => 'branch',
            'branch' => [
                'cases' => [
                    ['when' => ['in' => 'body', 'regex' => '(a+)+$'], 'response' => ['body' => 'x']],
                ],
                'default' => ['response' => ['body' => 'd']],
            ],
        ]];
        $this->factory->publish($this->fetcher, 'v1', 1, $this->factory->engineFiles(100, 100, $rules));

        $result = $this->updater('v1')->update();
        self::assertFalse($result->success);
        self::assertSame('redos', $result->status);
        self::assertNull($this->currentTarget());
    }

    public function test_widened_guard_passes_over_the_real_compiled_artifacts(): void
    {
        // The bundled release must itself pass the widened walk (fail-closed direction can't reject
        // the ground-truth artifacts). Screen every regex in the committed resources/compiled set.
        $guard = new \Funnypot\Core\Rules\ReDosGuard();
        $base = dirname(__DIR__, 2) . '/resources/compiled';
        foreach (['funnypot-attack.php', 'funnypot-routes.php', 'funnypot-routes-index.php', 'funnypot-param.php'] as $artifact) {
            $tree = require $base . '/' . $artifact;
            self::assertIsArray($tree, "{$artifact} must return an array");
            $guard->inspectArtifact($tree, $artifact);
        }
        $this->addToAssertionCount(1);
    }

    /** Largest regular-file size under $dir that is >= $threshold, else 0 (recursive). */
    private function largestFileUnder(string $dir, int $threshold): int
    {
        if (!is_dir($dir)) {
            return 0;
        }
        $max = 0;
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $item) {
            if ($item->isFile() && !$item->isLink()) {
                $size = (int) $item->getSize();
                if ($size >= $threshold && $size > $max) {
                    $max = $size;
                }
            }
        }

        return $max;
    }

    private function rmrf(string $dir): void
    {
        if (is_link($dir) || (!is_dir($dir) && is_file($dir))) {
            @unlink($dir);

            return;
        }
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_link($path)) {
                @unlink($path);
            } elseif (is_dir($path)) {
                $this->rmrf($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }
}
