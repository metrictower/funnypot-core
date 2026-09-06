<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Rules\PhpLiteralValidator;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Template\DirectiveRenderer;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The `traversal-read` behavior primitive and the Vite `/@fs/{path*}` slice it upgrades from an
 * echo into a bounded arbitrary-file-read emulation. Six well-known loot targets each serve a
 * believable, persona-synthetic file as text/plain; everything off the allow list falls through
 * to the dev-server not-found (the base 404).
 *
 * The load-bearing invariant these tests pin: the handler NEVER touches the real filesystem —
 * matching and content are pure string synthesis. A source-level guard asserts no fs-read call
 * appears in the handler/normalizer, and a functional test proves the served bytes are the
 * seed's PersonaIdentity, not any real file.
 */
final class TraversalReadTest extends TestCase
{
    private const PARAM_ARTIFACT = __DIR__ . '/../resources/compiled/funnypot-param.php';

    private const EMULATOR_SRC = __DIR__ . '/../src/Template/TemplateAttackEmulator.php';

    /** The shipped compiled `/@fs` param entry (carries behavior: traversal-read). */
    private function fsEntry(): array
    {
        $param = require self::PARAM_ARTIFACT;

        return $param['buckets']['@fs'][0];
    }

    /** Render the shipped `/@fs` entry for a given captured path + seed, through the render path. */
    private function render(string $path, int $seed = 12345): SynthesizedResponse
    {
        $resp = (new TemplateAttackEmulator([]))->renderRule($this->fsEntry(), ['path' => $path], $seed);
        self::assertNotNull($resp);

        return $resp;
    }

    /** A respond-mode engine (open gate) that serves the shipped param artifact end-to-end. */
    private function responder(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');

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
            true
        );
        // The /@fs route reflects the attacker path into its base body, so it is a reflecting decoy
        // that serves only from an isolated origin with request-bound evidence; these end-to-end
        // serve tests assert that path (test-only unconditional authorizer).
        $config->isolatedOrigin = true;
        $config->reflectorAuthorizer = static function (RequestContext $r, string $class): bool { return true; };

        return new Honeypot($store, $config);
    }

    // --- the six served targets, end-to-end through respond() ------------------------------

    public function test_each_target_serves_a_believable_body_as_plain_text(): void
    {
        $responder = $this->responder();
        $targets = [
            // path                                                   marker in the served body
            '/@fs/.env'                                            => 'AWS_ACCESS_KEY_ID=AKIA',
            '/@fs/home/deploy/.aws/credentials'                    => '[default]',
            '/@fs/var/www/html/wp-config.php'                      => "define('DB_PASSWORD'",
            '/@fs/proc/self/environ'                               => 'PATH=',
            '/@fs/etc/passwd'                                      => 'root:x:0:0',
            '/@fs/var/run/secrets/kubernetes.io/serviceaccount/token' => '.',
        ];

        foreach ($targets as $path => $marker) {
            $resp = $responder->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, $path);
            self::assertSame(200, $resp->status, $path);
            self::assertSame('text/plain; charset=utf-8', $resp->headers['Content-Type'], $path);
            self::assertStringContainsString($marker, $resp->body, $path);
        }
    }

    public function test_env_carries_db_and_aws_credentials(): void
    {
        $body = $this->render('.env')->body;

        self::assertStringContainsString('DB_PASSWORD=', $body);
        self::assertStringContainsString('AWS_ACCESS_KEY_ID=AKIA', $body);
        self::assertStringContainsString('AWS_SECRET_ACCESS_KEY=', $body);
    }

    public function test_aws_credentials_is_ini_shaped_with_the_key_pair(): void
    {
        $body = $this->render('.aws/credentials')->body;

        self::assertStringContainsString('[default]', $body);
        self::assertStringContainsString('aws_access_key_id = ', $body);
        self::assertStringContainsString('aws_secret_access_key = ', $body);
    }

    public function test_wp_config_is_served_as_raw_source_not_executable_php(): void
    {
        // A real arbitrary-file-read returns inert source bytes: the body IS PHP source, but the
        // Content-Type is text/plain, NOT text/x-php (which would be a tell — servers execute .php).
        $resp = $this->render('var/www/html/wp-config.php');

        self::assertStringContainsString("define('DB_PASSWORD'", $resp->body);
        self::assertStringContainsString('<?php', $resp->body);
        self::assertSame('text/plain; charset=utf-8', $resp->headers['Content-Type']);
        self::assertStringNotContainsString('x-php', $resp->headers['Content-Type']);
    }

    public function test_environ_is_nul_separated_with_path_marker(): void
    {
        $body = $this->render('proc/self/environ')->body;

        self::assertStringContainsString("\x00", $body, '/proc/self/environ is NUL-separated');
        self::assertStringContainsString('PATH=', $body);
    }

    public function test_passwd_carries_the_root_line(): void
    {
        self::assertStringContainsString('root:x:0:0', $this->render('etc/passwd')->body);
    }

    public function test_k8s_token_is_three_base64url_segments(): void
    {
        $body = trim($this->render('var/run/secrets/kubernetes.io/serviceaccount/token')->body);

        self::assertSame(1, preg_match('~^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$~', $body));
        self::assertCount(3, explode('.', $body));
    }

    // --- off the allow list -> the base 404, never a disclosure ----------------------------

    public function test_off_allowlist_path_falls_through_to_the_not_found(): void
    {
        $resp = $this->responder()->respond(new RequestContext('GET', '/@fs/var/log/syslog'));

        self::assertNotNull($resp);
        self::assertSame(404, $resp->status);
        self::assertStringContainsString('Not Found: /@fs/', $resp->body);
        self::assertStringNotContainsString('root:x:0:0', $resp->body);
        self::assertStringNotContainsString('AWS_ACCESS_KEY_ID', $resp->body);
    }

    // --- normalization: many spellings of the same target, no near-miss --------------------

    /** @dataProvider passwdSpellings */
    public function test_traversal_spellings_all_resolve_to_passwd(string $captured): void
    {
        $resp = $this->render($captured);

        self::assertSame(200, $resp->status, $captured);
        self::assertStringContainsString('root:x:0:0', $resp->body, $captured);
    }

    /** @return array<string,array{0:string}> */
    public static function passwdSpellings(): array
    {
        return [
            'percent-encoded + literal dotdot' => ['%2e%2e%2f../etc/passwd'],
            'plain dotdot'                      => ['../../etc/passwd'],
            'leading slash'                     => ['/etc/passwd'],
            'leading dot-slash'                 => ['./etc/passwd'],
            'exact'                             => ['etc/passwd'],
        ];
    }

    /** @dataProvider nearMisses */
    public function test_segment_boundary_rejects_near_misses(string $captured): void
    {
        // `.env` must not match sentry.env; `etc/passwd` must not match etc/xpasswd or xpasswd. A
        // near-miss falls through to the base 404 — no file is disclosed.
        $resp = $this->render($captured);

        self::assertSame(404, $resp->status, $captured);
        self::assertStringContainsString('Not Found: /@fs/', $resp->body, $captured);
    }

    /** @return array<string,array{0:string}> */
    public static function nearMisses(): array
    {
        return [
            'sentry.env vs .env'        => ['sentry.env'],
            'etc/xpasswd vs etc/passwd' => ['etc/xpasswd'],
            'xpasswd vs etc/passwd'     => ['xpasswd'],
            'basename mismatch'         => ['not-wp-config.php'],
        ];
    }

    // --- the content is persona-synthetic, not real bytes ----------------------------------

    public function test_served_credentials_are_the_seeds_persona_not_a_real_file(): void
    {
        // The disclosure bytes are a pure function of the seed's PersonaIdentity — proof the handler
        // synthesizes the "file" and never reads one off disk.
        $seed = 20260822;
        $persona = PersonaIdentity::fromSeed($seed);
        $body = $this->render('.aws/credentials', $seed)->body;

        self::assertStringContainsString($persona->field('cloud.aws.accessKeyId'), $body);
        self::assertStringContainsString($persona->field('cloud.aws.secretKey'), $body);
        self::assertStringContainsString($persona->field('cloud.aws.region'), $body);
    }

    public function test_aws_key_is_coherent_across_env_awscreds_and_dotenv_route(): void
    {
        // The coherence invariant behind fix #2: the credential-disclosure surfaces all resolve the
        // AWS key from the ONE persona identity, so a given deployment leaks a single, self-consistent
        // key everywhere — never a shared canned pick clusterable across honeypots. Prove the two
        // /@fs param surfaces AND the standalone /.env route agree on the seed's persona key pair.
        $seed = 20260822;
        $persona = PersonaIdentity::fromSeed($seed);
        $accessKey = (string) $persona->field('cloud.aws.accessKeyId');
        $secretKey = (string) $persona->field('cloud.aws.secretKey');
        self::assertStringStartsWith('AKIA', $accessKey);

        $surfaces = [
            '/@fs/.env'              => $this->render('.env', $seed)->body,
            '/@fs/.aws/credentials'  => $this->render('.aws/credentials', $seed)->body,
            '/.env'                  => (new DirectiveRenderer())->render($this->dotenvRouteBody(), [], $seed),
        ];
        foreach ($surfaces as $label => $body) {
            self::assertStringContainsString($accessKey, $body, "{$label} must disclose the seed's persona AWS access key id");
            self::assertStringContainsString($secretKey, $body, "{$label} must disclose the seed's persona AWS secret key");
        }
    }

    public function test_k8s_token_signature_is_seed_varying_and_carries_no_honeypot_marker(): void
    {
        // Fix #1: the served token must not be a byte-identical constant (a shared token clusters the
        // honeypot). The header+payload are canned but the signature is seed-derived, so two seeds
        // yield different tokens — and no segment decodes to a self-identifying marker.
        $path = 'var/run/secrets/kubernetes.io/serviceaccount/token';
        $a = trim($this->render($path, 111)->body);
        $b = trim($this->render($path, 222)->body);
        self::assertNotSame($a, $b, 'two deployments (seeds) must not serve an identical k8s token');
        self::assertSame(trim($this->render($path, 111)->body), $a, 'same seed must be byte-identical');

        // The signature segment (3rd) is what varies; header+payload are shared and constant.
        [$ha, $pa, $sa] = explode('.', $a);
        [$hb, $pb, $sb] = explode('.', $b);
        self::assertSame($ha, $hb);
        self::assertSame($pa, $pb);
        self::assertNotSame($sa, $sb, 'the signature segment must be seed-derived');

        $decoded = static function (string $seg): string {
            return (string) base64_decode(strtr($seg, '-_', '+/'));
        };
        foreach ([$a, $b] as $tok) {
            self::assertStringNotContainsStringIgnoringCase('funnypot', $tok);
            self::assertStringNotContainsStringIgnoringCase('fnpot', $decoded(explode('.', $tok)[0]));
        }
    }

    /** The committed route-dotenv body — the same string RouteTemplateEmulator renders for /.env. */
    private function dotenvRouteBody(): string
    {
        $routes = require __DIR__ . '/../resources/compiled/funnypot-routes.php';
        foreach ((array) $routes as $rule) {
            if (is_array($rule) && ($rule['id'] ?? null) === 'route-dotenv') {
                return (string) ($rule['body'] ?? '');
            }
        }
        self::fail('route-dotenv is not present in the compiled route artifact');
    }

    public function test_determinism_same_seed_identical_different_seed_differs(): void
    {
        self::assertSame($this->render('.env', 111)->body, $this->render('.env', 111)->body);
        self::assertNotSame($this->render('.env', 111)->body, $this->render('.env', 222)->body);

        // The persona credentials in .aws/credentials also diverge across seeds.
        self::assertNotSame(
            $this->render('.aws/credentials', 111)->body,
            $this->render('.aws/credentials', 222)->body
        );
    }

    // --- the ZERO-FS invariant (source-level guard) ----------------------------------------

    public function test_handler_and_normalizer_touch_no_filesystem(): void
    {
        // The one invariant that must never regress: the traversal-read handler + its canonicalizer
        // are pure string work. Assert no filesystem-read primitive appears anywhere between the
        // handler and the next unrelated method — a real file read would be an attacker-controlled
        // path landing on the host's disk.
        $src = (string) file_get_contents(self::EMULATOR_SRC);
        $start = strpos($src, 'private function handleTraversalRead');
        $end = strpos($src, 'function ruleById');
        self::assertNotFalse($start);
        self::assertNotFalse($end);
        self::assertGreaterThan($start, $end);
        $region = substr($src, $start, $end - $start);

        foreach (['file_get_contents', 'fopen', 'is_file', 'file_exists', 'realpath', 'glob', 'opendir', 'readfile', 'scandir', 'fread'] as $fn) {
            self::assertStringNotContainsString($fn, $region, "traversal-read must not call {$fn}");
        }
    }

    // --- the centralized C8 header-splitting guard still applies ----------------------------

    public function test_a_content_header_with_crlf_declines_the_whole_rule(): void
    {
        // Defense-in-depth: even if a CR/LF-bearing content header reached the runtime (the compiler
        // rejects it at build time), renderRule's single C8 guard declines the rule — never splits a
        // header. Directly-constructed entry, bypassing the compiler, to exercise the runtime guard.
        $entry = [
            'id' => 'param-traversal-crlf',
            'severity' => 'high',
            'tags' => [],
            'status' => 404,
            'method' => 'GET',
            'regex' => '^/@fs/(?P<path>.+)$',
            'captures' => ['path'],
            'response' => ['headers' => ['Content-Type' => 'text/plain; charset=utf-8'], 'body' => 'not found'],
            'behavior' => 'traversal-read',
            'traversal-read' => [
                'allow' => [
                    ['suffix' => '.env', 'content' => ['headers' => ['X-Bad' => "a\r\nInjected: 1"], 'body' => 'LEAK', 'status' => 200]],
                ],
            ],
        ];

        self::assertNull((new TemplateAttackEmulator([]))->renderRule($entry, ['path' => '.env'], 0));
    }

    // --- the compiled artifact is inert data + ids are disjoint from the attack set --------

    public function test_shipped_param_artifact_is_a_pure_literal(): void
    {
        self::assertTrue(
            (new PhpLiteralValidator())->isValidFile(self::PARAM_ARTIFACT),
            'the upgraded param artifact must validate as a pure array literal (it is require()d)'
        );
    }

    public function test_attack_and_param_rule_ids_are_disjoint(): void
    {
        // Belt-and-braces to the build-time collision guard: the runtime looks rules up by id across
        // BOTH sets (ruleById), so a shared id would resolve the wrong rule. Assert the COMMITTED
        // artifacts never collide.
        $attack = require __DIR__ . '/../resources/compiled/funnypot-attack.php';
        $attackIds = [];
        foreach ((array) $attack as $rule) {
            if (is_array($rule) && isset($rule['id'])) {
                $attackIds[(string) $rule['id']] = true;
            }
        }

        $param = require self::PARAM_ARTIFACT;
        $paramIds = [];
        foreach ((array) ($param['buckets'] ?? []) as $entries) {
            foreach ((array) $entries as $entry) {
                if (is_array($entry) && isset($entry['id'])) {
                    $paramIds[(string) $entry['id']] = true;
                }
            }
        }

        self::assertNotEmpty($attackIds);
        self::assertNotEmpty($paramIds);
        self::assertSame([], array_intersect_key($attackIds, $paramIds), 'attack and param rule ids must be disjoint');
    }

    // --- the fingerprint CI gate scans traversal-read content (guard the descent) ----------

    public function test_ci_gate_descends_into_traversal_read_content(): void
    {
        // A clean fixture passes (control: the gate + the descent run without a false positive).
        [$cleanCode] = $this->runGate($this->paramFixture('APP_ENV=production'));
        self::assertSame(0, $cleanCode, 'a clean traversal-read body must pass the gate');

        // Plant a denylist signature ONLY inside a traversal-read allow body — the top-level
        // response body stays clean, so a catch can ONLY have come from the descent. If someone
        // removed the descent, this leak would slip through (exit 0) and the test fails.
        [$leakCode, $leakOut] = $this->runGate($this->paramFixture('blocked by OWASP_CRS ruleset'));
        self::assertSame(1, $leakCode, 'a leak in a traversal-read body must fail the gate');
        // FP-0262: the walker gate names the exact served key-path (more precise than the rule id),
        // so the message pins the traversal-read content body the descent reached.
        self::assertStringContainsString('traversal-read.allow.0.content.body', $leakOut);
        self::assertStringContainsString('OWASP_CRS', $leakOut);
    }

    /**
     * A param artifact whose top-level response is clean but whose traversal-read allow body carries
     * $body — so the ONLY leak surface is the descent.
     */
    private function paramFixture(string $body): string
    {
        $artifact = [
            'schema' => 1,
            'buckets' => [
                '@fs' => [
                    [
                        'id' => 'param-fixture-leak',
                        'severity' => 'high',
                        'tags' => [],
                        'status' => 404,
                        'method' => 'GET',
                        'regex' => '^/@fs/(?P<path>.+)$',
                        'captures' => ['path'],
                        'response' => ['headers' => ['Content-Type' => 'text/plain'], 'body' => 'clean not found'],
                        'behavior' => 'traversal-read',
                        'traversal-read' => [
                            'allow' => [
                                ['suffix' => '.env', 'content' => ['headers' => ['Content-Type' => 'text/plain'], 'body' => $body, 'status' => 200]],
                            ],
                        ],
                    ],
                ],
            ],
        ];
        $php = "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($artifact, true) . ";\n";
        $path = sys_get_temp_dir() . '/funnypot-fp-' . bin2hex(random_bytes(6)) . '.php';
        file_put_contents($path, $php);

        return $path;
    }

    /**
     * @return array{0:int,1:string} [exitCode, combined output]
     */
    private function runGate(string $indexPath): array
    {
        $cmd = escapeshellarg(PHP_BINARY) . ' '
            . escapeshellarg(__DIR__ . '/../scripts/ci/check-fingerprint-safety.php')
            . ' --index=' . escapeshellarg($indexPath) . ' 2>&1';
        $out = [];
        $code = 0;
        exec($cmd, $out, $code);
        @unlink($indexPath);

        return [$code, implode("\n", $out)];
    }
}
