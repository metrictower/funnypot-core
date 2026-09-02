<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Attack;

use Funnypot\Core\Attack\AttackBodies;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * FP-0279 — the AttackBodies helper contract. AttackBodies is the single source of truth for the
 * INCIDENTAL (non-marker) content of the TIER-2 static attack-class bodies: the SQLi error frame's
 * PHP-warning wrapper / offending-token fragment / docroot path+line, and the SSTI/CRS-xss decline
 * pages' titles + copy. It must be a pure deterministic function of the deploy identity seed
 * (SubSeed::index/pick, never the 64-bit-only child seed) while NEVER dropping an exploit-confirmation
 * marker at any seed — including seed 0, the compile-time assertMarkers render.
 *
 * These assertions FAIL against pre-FP-0279 code (there was no AttackBodies and the bodies were fleet
 * constants). Fixtures: the committed templates/attack/50-sqli.yaml + templates/attack-crs/950-crs-sqli.yaml
 * + templates/param/20-sqli-differential.yaml (template-side marker pin) and the compiled artifacts
 * resources/compiled/funnypot-attack.php + funnypot-param.php (compiled coherence).
 */
final class AttackBodiesTest extends TestCase
{
    private const ROOT = __DIR__ . '/../..';

    /** sqlmap's PRIMARY MySQL error fingerprints — quoted with provenance (data/xml/errors.xml). */
    private const SQLMAP_MYSQL = '/SQL syntax.*MySQL/';
    private const SQLMAP_MANUAL = '/check the manual that (corresponds to|fits) your MySQL server version/';

    /**
     * The seed sweep — 0 FIRST (the compile-time assertMarkers seed), then small ints, the two gate
     * materials, the fleet defaults, and a large value. Marker survival is proven at EVERY one.
     *
     * @return array<string,int>
     */
    private function sweepSeeds(): array
    {
        return [
            'seed-0' => 0,
            'seed-1' => 1,
            'seed-5' => 5,
            'seed-7' => 7,
            'seed-99' => 99,
            "material-''" => PersonaIdentity::seedFromMaterial(''),
            "material-'funnypot'" => PersonaIdentity::seedFromMaterial('funnypot'),
            "material-'fp-0276-sample-a'" => PersonaIdentity::seedFromMaterial('fp-0276-sample-a'),
            "material-'fp-0276-sample-b'" => PersonaIdentity::seedFromMaterial('fp-0276-sample-b'),
            'seed-20260902' => 20260902,
            'seed-large' => 2147483646,
        ];
    }

    /** Assemble the served SQLi body EXACTLY as the template does. */
    private function sqliBody(int $seed): string
    {
        $slug = (string) PersonaIdentity::fromSeed($seed)->field('company.slug');

        return AttackBodies::sqli($seed, 'prefix', $slug)
            . AttackBodies::MYSQL_1064
            . AttackBodies::sqli($seed, 'near', $slug)
            . "' at line 1"
            . AttackBodies::sqli($seed, 'suffix', $slug)
            . "\n";
    }

    // --- §4.1 marker preservation at every seed (incl. 0) --------------------------------------------

    public function test_every_exploit_confirmation_marker_survives_at_every_seed(): void
    {
        foreach ($this->sweepSeeds() as $label => $seed) {
            $body = $this->sqliBody($seed);
            self::assertStringContainsString('SQL syntax', $body, "expect: pin at {$label}");
            self::assertStringContainsString(AttackBodies::MYSQL_1064, $body, "full 1064 sentence at {$label}");
            self::assertStringContainsString('You have an error in your SQL syntax', $body, "nuclei bw at {$label}");
            self::assertStringContainsString('error in your SQL syntax', $body, "nuclei bw at {$label}");
            self::assertStringContainsString("' at line 1", $body, "the '\\' at line 1' tail at {$label}");
            self::assertSame(1, preg_match(self::SQLMAP_MYSQL, $body), "sqlmap SQL syntax.*MySQL at {$label}");
            self::assertSame(1, preg_match(self::SQLMAP_MANUAL, $body), "sqlmap check-the-manual at {$label}");
            self::assertSame(1, preg_match("/near '.+' at line 1/", $body), "near fragment non-empty at {$label}");
            self::assertStringNotContainsString("''''", $body, "no quadrupled quote at {$label}");
        }
    }

    public function test_framed_seeds_carry_the_sqlstate_marker_and_a_persona_rooted_docroot(): void
    {
        $framedSeen = false;
        foreach ($this->sweepSeeds() as $label => $seed) {
            $frame = AttackBodies::sqliDraws($seed)['frame'];
            if ($frame === 0) {
                continue;
            }
            $framedSeen = true;
            $slug = (string) PersonaIdentity::fromSeed($seed)->field('company.slug');
            $body = $this->sqliBody($seed);
            self::assertSame(1, preg_match('/SQLSTATE\[\d+\]: Syntax error or access violation/', $body), "SQLSTATE at {$label}");
            // The docroot is rooted at the SAME slug phpinfo advertises — never a fixed /var/www/html/.
            $pattern = '#^ in <b>/var/www/' . preg_quote($slug, '#')
                . '/(public|app|includes|inc|lib|src|classes)/[0-9A-Za-z]+\.php</b> on line <b>\d{2,3}</b><br />$#';
            self::assertSame(1, preg_match($pattern, (string) AttackBodies::sqli($seed, 'suffix', $slug)), "docroot-rooted suffix at {$label}");
        }
        self::assertTrue($framedSeen, 'the sweep must include at least one framed (non-bare) seed');
    }

    public function test_no_output_ever_carries_a_mysqli_or_html_docroot_or_directive_tell(): void
    {
        foreach ($this->sweepSeeds() as $label => $seed) {
            $body = $this->sqliBody($seed);
            self::assertSame(0, preg_match('/mysqli/i', $body), "no mysqli (contradicts phpinfo PDO-only list) at {$label}");
            self::assertStringNotContainsString('/var/www/html', $body, "no fixed docroot at {$label}");
            self::assertStringNotContainsString('{{', $body, "no unresolved directive at {$label}");
            self::assertSame(0, preg_match('/[\r\x00]/', $body), "no CR/NUL at {$label}");
            // near carries no newline (a body-only directive keeps its single \n only in the frame prefix).
            self::assertStringNotContainsString("\n", (string) AttackBodies::sqli($seed, 'near', 'acme'), "near has no newline at {$label}");
        }
    }

    public function test_line_numbers_are_bounded_away_from_a_six_digit_denied_run(): void
    {
        for ($i = 0; $i < 64; $i++) {
            $seed = PersonaIdentity::seedFromMaterial('fp-0279-line-' . $i);
            $line = AttackBodies::sqliDraws($seed)['line'];
            self::assertGreaterThanOrEqual(10, $line);
            self::assertLessThanOrEqual(249, $line);
        }
    }

    public function test_every_rendered_variant_is_fingerprint_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach ($this->sweepSeeds() as $label => $seed) {
            self::assertSame([], $guard->scan($this->sqliBody($seed)), "G1 self-check SQLi at {$label}");
            foreach (AttackBodies::PAGE_KINDS as $kind) {
                $company = (string) PersonaIdentity::fromSeed($seed)->field('company.name');
                $page = (string) AttackBodies::page($seed, $kind, 'title', $company)
                    . (string) AttackBodies::page($seed, $kind, 'body', $company);
                self::assertSame([], $guard->scan($page), "G1 self-check page:{$kind} at {$label}");
            }
        }
    }

    public function test_a_hostile_or_empty_slug_falls_back_without_markup_or_crlf(): void
    {
        foreach (["'<x>'", "a\nb", '{{evil}}', 'a b', '', 'a"b', 'a&b'] as $slug) {
            $suffix = (string) AttackBodies::sqli(7, 'suffix', $slug); // frame 7 is a framed seed
            if ($slug !== '') {
                self::assertStringNotContainsString($slug, $suffix, 'hostile slug never embedded verbatim');
            }
            // A hostile/empty slug drops the slug segment entirely: /var/www/<dir><file>.
            self::assertSame(1, preg_match('#/var/www/(public|app|includes|inc|lib|src|classes)/#', $suffix), 'hostile slug -> no slug segment');
            self::assertSame(0, preg_match('/[<>&"\r\n]/', str_replace(['<b>', '</b>', '<br />'], '', $suffix)), 'no injected markup/CRLF beyond the fixed <b>/<br /> frame');
        }
    }

    // --- pages ---------------------------------------------------------------------------------------

    public function test_page_titles_embed_the_escaped_company_name(): void
    {
        // Every title option embeds {c}, so the escaped company always appears (G4 sees a diff per persona).
        self::assertStringContainsString('A&amp;B', (string) AttackBodies::page(0, 'home', 'title', 'A&B'));
        self::assertStringContainsString('A&amp;B', (string) AttackBodies::page(0, 'search', 'title', 'A&B'));
        self::assertStringNotContainsString('A&B', (string) AttackBodies::page(0, 'home', 'title', 'A&B'));
        foreach ($this->sweepSeeds() as $label => $seed) {
            foreach (AttackBodies::PAGE_KINDS as $kind) {
                foreach (AttackBodies::PAGE_SLOTS as $slot) {
                    $v = (string) AttackBodies::page($seed, $kind, $slot, 'Acme');
                    self::assertNotSame('', $v, "page {$kind}.{$slot} non-empty at {$label}");
                    self::assertStringNotContainsString('{{', $v, "page {$kind}.{$slot} no directive at {$label}");
                    // No 6-digit denied run (the real fingerprint invariant; body copy may carry an <h1>/<h2>).
                    self::assertSame(0, preg_match('/\b9\d{5}\b/', $v), "page {$kind}.{$slot} carries no denied digit run at {$label}");
                }
                // Titles carry no digit at all.
                self::assertSame(0, preg_match('/\d/', (string) AttackBodies::page($seed, $kind, 'title', 'Acme')), "title {$kind} carries no digit at {$label}");
                self::assertStringContainsString('Acme', (string) AttackBodies::page($seed, $kind, 'title', 'Acme'), "title carries company at {$label}");
            }
        }
    }

    // --- template-side pin: the marker is authored bytes OUTSIDE any directive ------------------------

    public function test_every_sqli_template_carries_the_marker_verbatim_outside_a_directive(): void
    {
        $literal = AttackBodies::MYSQL_1064 . "{{attack.sqli.near}}' at line 1{{attack.sqli.suffix}}";
        foreach ([
            'templates/attack/50-sqli.yaml' => 'response.body',
            'templates/attack-crs/950-crs-sqli.yaml' => 'response.body',
        ] as $file => $_) {
            $doc = Yaml::parseFile(self::ROOT . '/' . $file);
            $body = (string) $doc['response']['body'];
            self::assertStringStartsWith('{{attack.sqli.prefix}}', $body, "{$file} starts with the frame prefix directive");
            self::assertStringContainsString($literal, $body, "{$file} carries the 1064 sentence + tail as literal bytes");
        }
        // 50-sqli's expect: pin is unchanged.
        $sqli = Yaml::parseFile(self::ROOT . '/templates/attack/50-sqli.yaml');
        self::assertContains('SQL syntax', (array) $sqli['expect']);

        // The param breaker case carries the same literal marker string.
        $param = Yaml::parseFile(self::ROOT . '/templates/param/20-sqli-differential.yaml');
        $breaker = null;
        foreach ((array) $param['branch']['cases'] as $case) {
            if (($case['response']['status'] ?? null) === 500) {
                $breaker = (string) $case['response']['body'];
            }
        }
        self::assertNotNull($breaker, 'the 500 breaker case must exist');
        self::assertStringStartsWith('{{attack.sqli.prefix}}', (string) $breaker);
        self::assertStringContainsString($literal, (string) $breaker);
    }

    // --- unknown forms + isKnownForm -----------------------------------------------------------------

    public function test_unknown_forms_resolve_to_null_and_isKnownForm_is_exact(): void
    {
        self::assertNull(AttackBodies::resolve('sqli.bogus', 5, 'Acme', 'acme'));
        self::assertNull(AttackBodies::resolve('page.title:zz', 5, 'Acme', 'acme'));
        self::assertNull(AttackBodies::resolve('page.headline:home', 5, 'Acme', 'acme'));
        self::assertNull(AttackBodies::resolve('nope', 5, 'Acme', 'acme'));
        self::assertNull(AttackBodies::sqli(5, 'bogus', 'acme'));
        self::assertNull(AttackBodies::page(5, 'zz', 'title', 'Acme'));
        self::assertNull(AttackBodies::page(5, 'home', 'zz', 'Acme'));

        foreach (['sqli.prefix', 'sqli.near', 'sqli.suffix', 'page.title:home', 'page.body:home', 'page.title:search', 'page.body:search'] as $form) {
            self::assertTrue(AttackBodies::isKnownForm($form), "known: {$form}");
        }
        foreach (['sqli.bogus', 'page.title:zz', 'page.zz:home', 'nope', 'sqli', 'page.title', 'page'] as $form) {
            self::assertFalse(AttackBodies::isKnownForm($form), "unknown: {$form}");
        }
    }

    public function test_source_never_calls_the_64_bit_only_subseed_int(): void
    {
        $src = (string) file_get_contents(self::ROOT . '/src/Attack/AttackBodies.php');
        self::assertStringNotContainsString('SubSeed::int(', $src, 'SubSeed::int() is 64-bit-only — never on the served path');
    }

    // --- §4.2 cross-deploy variance ------------------------------------------------------------------

    public function test_sqli_draws_vary_across_deploys(): void
    {
        $tuples = [];
        $frames = $nears = $dirs = $files = $lines = [];
        $bodies = [];
        $bothPdoFrames = [];
        for ($i = 0; $i < 64; $i++) {
            $seed = PersonaIdentity::seedFromMaterial('fp-0279-m' . $i);
            $d = AttackBodies::sqliDraws($seed);
            $tuples[] = $d['frame'] . '|' . $d['near'] . '|' . $d['dir'] . '|' . $d['file'] . '|' . $d['line'];
            $frames[$d['frame']] = true;
            $nears[$d['near']] = true;
            $dirs[$d['dir']] = true;
            $files[$d['file']] = true;
            $lines[$d['line']] = true;
            if ($d['frame'] >= 1 && $d['frame'] <= 3) {
                $bothPdoFrames['query'] = true;
            } elseif ($d['frame'] >= 4) {
                $bothPdoFrames['execute'] = true;
            }
            $bodies[] = $this->sqliBody($seed);
        }
        // Distinctness on the DRAW TUPLE (not the assembled body — F0 collapses dir/file/line).
        self::assertGreaterThanOrEqual(56, count(array_unique($tuples)), 'draw tuples distinct across 64 deploys');
        self::assertGreaterThanOrEqual(40, count(array_unique($bodies)), 'assembled bodies distinct (loose floor)');
        // Every axis lives.
        self::assertGreaterThanOrEqual(2, count($frames), 'frame axis lives');
        self::assertGreaterThanOrEqual(2, count($nears), 'near axis lives');
        self::assertGreaterThanOrEqual(2, count($dirs), 'dir axis lives');
        self::assertGreaterThanOrEqual(2, count($files), 'file axis lives');
        self::assertGreaterThanOrEqual(2, count($lines), 'line axis lives');
        // Both PDO frame shapes occur.
        self::assertArrayHasKey('query', $bothPdoFrames, 'the PDO::query() frame occurs');
        self::assertArrayHasKey('execute', $bothPdoFrames, 'the PDOStatement::execute() frame occurs');
    }

    public function test_pages_vary_across_deploys(): void
    {
        $home = [];
        for ($i = 0; $i < 64; $i++) {
            $seed = PersonaIdentity::seedFromMaterial('fp-0279-p' . $i);
            $company = (string) PersonaIdentity::fromSeed($seed)->field('company.name');
            $home[] = AttackBodies::page($seed, 'home', 'title', $company) . '|' . AttackBodies::page($seed, 'home', 'body', $company);
        }
        self::assertGreaterThanOrEqual(30, count(array_unique($home)), 'distinct home pages across 64 deploys');
    }

    // --- §4.3 within-deploy determinism + compiled coherence -----------------------------------------

    public function test_accessors_are_deterministic_per_seed(): void
    {
        foreach ($this->sweepSeeds() as $label => $seed) {
            self::assertSame($this->sqliBody($seed), $this->sqliBody($seed), "SQLi determinism at {$label}");
            self::assertSame(
                AttackBodies::page($seed, 'home', 'title', 'Acme'),
                AttackBodies::page($seed, 'home', 'title', 'Acme'),
                "page determinism at {$label}"
            );
        }
    }

    public function test_the_three_sqli_surfaces_and_two_ssti_pages_are_byte_coherent_per_deploy(): void
    {
        $attack = require self::ROOT . '/resources/compiled/funnypot-attack.php';
        $bodyOf = static function (array $rules, string $id): string {
            foreach ($rules as $rule) {
                if (is_array($rule) && ($rule['id'] ?? null) === $id) {
                    return (string) $rule['response']['body'];
                }
            }
            return '__missing__';
        };
        $sqliBody = $bodyOf($attack, 'attack-sqli');
        $crsSqliBody = $bodyOf($attack, 'attack-crs-sqli');
        self::assertStringContainsString('{{attack.sqli.prefix}}', $sqliBody);
        self::assertSame($sqliBody, $crsSqliBody, 'attack-sqli and attack-crs-sqli store the identical directive string');

        // The param breaker case body equals the same string.
        $param = require self::ROOT . '/resources/compiled/funnypot-param.php';
        $breaker = null;
        foreach ($this->flattenParam($param) as $entry) {
            if (($entry['id'] ?? null) !== 'param-sqli-differential') {
                continue;
            }
            foreach ((array) ($entry['branch']['cases'] ?? []) as $case) {
                if ((int) ($case['response']['status'] ?? 0) === 500) {
                    $breaker = (string) ($case['response']['body'] ?? '');
                }
            }
        }
        self::assertNotNull($breaker, 'compiled param breaker case body found');
        self::assertSame($sqliBody, $breaker, 'the param breaker stores the identical SQLi directive string');

        // The two SSTI decline pages are identical (one host, one home page).
        self::assertSame($bodyOf($attack, 'attack-ssti-numeric'), $bodyOf($attack, 'attack-ssti-multifence'));

        // Rendered through ONE deploy renderer at two render seeds ⇒ deploy-keyed, not request-keyed.
        $deploySeed = PersonaIdentity::seedFromMaterial('fp-0279-coherence');
        $r = new DirectiveRenderer($deploySeed);
        self::assertSame($r->render($sqliBody, [], 1), $r->render($crsSqliBody, [], 2), 'the SQLi story is one shape across surfaces + render seeds on a deploy');
        self::assertSame($r->render($breaker, [], 5), $r->render($sqliBody, [], 9));
    }

    /**
     * @param array<int|string,mixed> $raw
     * @return list<array<string,mixed>>
     */
    private function flattenParam(array $raw): array
    {
        if (!isset($raw['buckets']) || !is_array($raw['buckets'])) {
            return array_values(array_filter($raw, 'is_array'));
        }
        $flat = [];
        foreach ($raw['buckets'] as $entries) {
            foreach ((array) $entries as $entry) {
                if (is_array($entry)) {
                    $flat[] = $entry;
                }
            }
        }

        return $flat;
    }

    // --- §4.4/§4.5 compile-time lint: markers live, closed vocabulary ---------------------------------

    public function test_the_shipped_sqli_body_compiles_through_assertMarkers_at_seed_zero(): void
    {
        // POSITIVE control: the §2.2 body with expect: ['SQL syntax'] compiles (proves the seed-0 render
        // carries the marker by construction). NEGATIVE control: remove the sentence and the build fails.
        $ok = $this->compileScratch([
            'id' => 'scratch-sqli-ok',
            'priority' => 50,
            'tags' => ['attack', 'sqli'],
            'match' => [['in' => 'request', 'regex' => 'union select']],
            'response' => ['headers' => ['Content-Type' => 'text/html; charset=utf-8'], 'body' => "{{attack.sqli.prefix}}" . AttackBodies::MYSQL_1064 . "{{attack.sqli.near}}' at line 1{{attack.sqli.suffix}}\n"],
            'expect' => ['SQL syntax'],
        ]);
        self::assertNotNull($ok);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('expected marker');
        $this->compileScratch([
            'id' => 'scratch-sqli-nomarker',
            'priority' => 50,
            'tags' => ['attack', 'sqli'],
            'match' => [['in' => 'request', 'regex' => 'union select']],
            // The marker exists ONLY inside a directive that renders '' at some seeds → assertMarkers must fail.
            'response' => ['headers' => ['Content-Type' => 'text/html; charset=utf-8'], 'body' => "{{attack.sqli.prefix}}nothing here{{attack.sqli.suffix}}\n"],
            'expect' => ['SQL syntax'],
        ]);
    }

    /** @dataProvider badForms */
    public function test_unknown_attack_form_is_rejected_at_compile(string $form): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('unknown attack form');
        $this->compileScratch([
            'id' => 'scratch-attack-typo',
            'priority' => 60,
            'tags' => ['attack'],
            'match' => [['in' => 'request', 'regex' => 'x']],
            'response' => ['headers' => ['Content-Type' => 'text/html; charset=utf-8'], 'body' => '{{' . $form . '}}'],
        ]);
    }

    /** @return array<string,array{0:string}> */
    public function badForms(): array
    {
        return [
            'sqli.bogus' => ['attack.sqli.bogus'],
            'page.title:zz' => ['attack.page.title:zz'],
            'attack.nope' => ['attack.nope'],
        ];
    }

    public function test_attack_directive_in_a_header_value_is_rejected_as_body_only(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('body-only');
        $this->compileScratch([
            'id' => 'scratch-attack-header',
            'priority' => 60,
            'tags' => ['attack'],
            'match' => [['in' => 'request', 'regex' => 'x']],
            'response' => ['headers' => ['Content-Type' => 'text/html; charset=utf-8', 'X-Debug' => '{{attack.sqli.prefix}}'], 'body' => 'ok'],
        ]);
    }

    /**
     * Compile a single scratch attack template through the real EmulatorCompiler; return its rule.
     *
     * @param array<string,mixed> $doc
     * @return array<string,mixed>|null
     */
    private function compileScratch(array $doc): ?array
    {
        $dir = sys_get_temp_dir() . '/funnypot-attackbodies-' . getmypid() . '-' . uniqid();
        self::assertTrue(mkdir($dir, 0775, true) || is_dir($dir));
        file_put_contents($dir . '/rule.yaml', Yaml::dump($doc, 8, 2));
        try {
            $rules = (new EmulatorCompiler())->compile($dir);
        } finally {
            @unlink($dir . '/rule.yaml');
            @rmdir($dir);
        }
        foreach ($rules as $rule) {
            if (is_array($rule) && ($rule['id'] ?? null) === $doc['id']) {
                return $rule;
            }
        }

        return null;
    }
}
