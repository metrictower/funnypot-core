<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * FP-0299 — authored lures carry no demo brand. Every served response leaf must name the ONE
 * per-deploy PersonaIdentity, never a fixed `example.com` / `@acme` placeholder: a lure that
 * discloses a company the rest of the host does not is itself a fingerprint. The four surfaces
 * that still shipped the placeholders (git config, Apache server-status, npmrc, Citrix Bleed) now
 * project the persona company domain / slug, so a single deployment discloses exactly one company.
 *
 * The compiled-leaf sweep is a no-demo-brand LAW for served bytes, not a blanket ban on the string
 * "acme": ACME certificate-challenge route evidence (a protocol, not the Acme demo company) lives in
 * detection selectors of the external nuclei corpus and is deliberately out of scope — this test
 * reads only the authored route/attack artifacts and only their response body/header leaves.
 */
final class DemoBrandSweepTest extends TestCase
{
    private const ROUTES = __DIR__ . '/../resources/compiled/funnypot-routes.php';

    private const ATTACK = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private const TPL = __DIR__ . '/../templates';

    /** The four authored rules this ticket de-brands, id => compiled artifact it lives in. */
    private const RULES = [
        'route-git-config' => self::ROUTES,
        'route-apache-server-status' => self::ROUTES,
        'route-npmrc' => self::ROUTES,
        'attack-citrix-bleed-4966' => self::ATTACK,
    ];

    /** Deploy materials swept: the two fleet defaults, plus a per-deploy spread for variance. */
    private function materials(): array
    {
        $mats = ['', 'funnypot'];
        for ($i = 0; $i < 40; $i++) {
            $mats[] = 'fp-0299-' . $i;
        }

        return $mats;
    }

    /** Two render seeds (per-Host crc32), so the persona claim holds across hosts, not just one. */
    private function renderSeeds(): array
    {
        return [crc32('a.example|s'), crc32('b.example|s')];
    }

    // --- T1: no demo brand survives in any authored served leaf ------------------------------------

    public function test_t1_no_demo_brand_in_compiled_served_leaves(): void
    {
        $leaves = [];
        foreach ([self::ROUTES, self::ATTACK] as $artifact) {
            foreach ((array) (require $artifact) as $rule) {
                if (is_array($rule)) {
                    foreach ($this->servedLeaves($rule) as $leaf) {
                        $leaves[] = $leaf;
                    }
                }
            }
        }
        // The sweep must have found real served content (guards against a walker that visits nothing).
        self::assertNotEmpty($leaves, 'the served-leaf walker must visit at least one response leaf');

        foreach ($leaves as $leaf) {
            self::assertFalse($this->hasDemoBrand($leaf), 'no served leaf may disclose a demo brand: ' . $leaf);
        }
    }

    // --- AC#4: the sweep is non-vacuous — each de-branded rule is present with served content -------

    public function test_t2_each_debranded_rule_is_present_and_non_empty(): void
    {
        foreach (self::RULES as $id => $artifact) {
            $rule = $this->rule($id, $artifact);
            self::assertNotNull($rule, "rule '{$id}' must be present in its compiled artifact");
            self::assertNotEmpty(
                $this->servedLeaves($rule),
                "rule '{$id}' must expose served leaves so the sweep cannot pass on an empty set"
            );
        }
    }

    // --- Control: the ban is precise — an ACME certificate-challenge path is NOT banned -------------

    public function test_t3_ban_is_a_demo_brand_law_not_a_blanket_acme_ban(): void
    {
        // Real ACME protocol evidence (certificate challenge) — must read as clean.
        self::assertFalse(
            $this->hasDemoBrand('GET /.well-known/acme-challenge/tokenXYZ HTTP/1.1'),
            'an ACME certificate-challenge path is legitimate and must not trip the demo-brand ban'
        );
        // The two literals the ban DOES catch — proves the predicate actually bites.
        self::assertTrue($this->hasDemoBrand('@acme:registry=https://npm.pkg.github.com'), '@acme scope is a demo brand');
        self::assertTrue($this->hasDemoBrand('https://gateway.Example.COM/oauth/idp'), 'example.com is a demo brand (case-insensitive)');
    }

    // --- T4: the four rules project the persona domain / slug, coherently and deterministically -----

    public function test_t4_four_rules_project_persona_identity(): void
    {
        $domains = [];
        $slugs = [];
        $sentinel = ['host' => 'evil.attacker.invalid', 0 => 'evil.attacker.invalid', 'sentinel' => 'evil.attacker.invalid'];

        foreach ($this->materials() as $mat) {
            $deploySeed = PersonaIdentity::seedFromMaterial($mat);
            $persona = PersonaIdentity::fromSeed($deploySeed);
            $domain = (string) $persona->field('company.domain');
            $slug = (string) $persona->field('company.slug');
            $domains[] = $domain;
            $slugs[] = $slug;

            foreach ($this->renderSeeds() as $renderSeed) {
                $git = $this->render('route-git-config', self::ROUTES, $deploySeed, $renderSeed, $sentinel);
                $apache = $this->render('route-apache-server-status', self::ROUTES, $deploySeed, $renderSeed, $sentinel);
                $npm = $this->render('route-npmrc', self::ROUTES, $deploySeed, $renderSeed, $sentinel);
                $citrix = $this->render('attack-citrix-bleed-4966', self::ATTACK, $deploySeed, $renderSeed, $sentinel);

                foreach ([$git, $apache, $npm, $citrix] as $body) {
                    // No unresolved directive escaped, and no attacker-supplied sentinel reflected in
                    // (the persona is deploy-derived, so a Host-header change cannot rewrite the lure).
                    self::assertStringNotContainsString('{{', $body, "m=[{$mat}] no raw directive survives render");
                    self::assertStringNotContainsString('evil.attacker.invalid', $body, "m=[{$mat}] no request-derived host reflects into the lure");
                    self::assertFalse($this->hasDemoBrand($body), "m=[{$mat}] rendered lure carries no demo brand");
                }

                // Exact projections (spec §2).
                self::assertStringContainsString('https://git.' . $domain . '/internal/', $git, "m=[{$mat}] git remote host is the persona domain");
                self::assertSame(
                    1,
                    preg_match('#url = https://git\.' . preg_quote($domain, '#') . '/internal/[a-z]+\.git#', $git),
                    "m=[{$mat}] git remote URL grammar"
                );

                self::assertStringContainsString('Apache Server Status for status.' . $domain . ' (via 192.0.2.10)', $apache, "m=[{$mat}] apache title host");
                self::assertSame(2, substr_count($apache, 'www.' . $domain), "m=[{$mat}] both apache vhost rows carry the persona domain");
                // RFC-5737 client IPs and the loopback via-address are preserved.
                foreach (['198.51.100.24', '203.0.113.7', '192.0.2.10'] as $ip) {
                    self::assertStringContainsString($ip, $apache, "m=[{$mat}] apache preserves RFC-5737 client {$ip}");
                }

                self::assertSame(
                    1,
                    preg_match('/^@' . preg_quote($slug, '/') . ':registry=https:\/\/npm\.pkg\.github\.com$/m', $npm),
                    "m=[{$mat}] npm scope is @<slug> with the registry grammar intact"
                );

                // Citrix: issuer and authorization share one gateway origin; only the latter appends /login.
                self::assertSame(1, preg_match('/"issuer":"([^"]+)"/', $citrix, $iss), "m=[{$mat}] citrix issuer present");
                self::assertSame(1, preg_match('/"authorization_endpoint":"([^"]+)"/', $citrix, $aut), "m=[{$mat}] citrix authorization present");
                self::assertSame('https://gateway.' . $domain . '/oauth/idp', $iss[1], "m=[{$mat}] citrix issuer host is the persona gateway");
                self::assertSame($iss[1] . '/login', $aut[1], "m=[{$mat}] citrix authorization = issuer + /login (same origin)");
                self::assertNotNull(json_decode($this->firstLine($citrix)), "m=[{$mat}] citrix leak line stays valid JSON");

                // Determinism: the same (deploy, render) point renders byte-identical.
                self::assertSame($git, $this->render('route-git-config', self::ROUTES, $deploySeed, $renderSeed), "m=[{$mat}] git render is deterministic");
                self::assertSame($citrix, $this->render('attack-citrix-bleed-4966', self::ATTACK, $deploySeed, $renderSeed), "m=[{$mat}] citrix render is deterministic");
            }
        }

        // Cross-deploy variance: the sweep spans more than one company domain and slug.
        self::assertGreaterThan(1, count(array_unique($domains)), 'the material sweep must span more than one company domain');
        self::assertGreaterThan(1, count(array_unique($slugs)), 'the material sweep must span more than one company slug');
    }

    // --- T5: every exploit-confirmation marker survives; rendered bytes are fingerprint-clean -------

    public function test_t5_markers_survive_and_bytes_are_fingerprint_clean(): void
    {
        $expect = [
            'route-git-config' => [self::ROUTES, $this->expectOf('route/10-git-config.yaml')],
            'route-apache-server-status' => [self::ROUTES, $this->expectOf('route/80-apache-server-status.yaml')],
            'route-npmrc' => [self::ROUTES, $this->expectOf('route/95-npmrc.yaml')],
            'attack-citrix-bleed-4966' => [self::ATTACK, $this->expectOf('attack/84-citrix-bleed.yaml')],
        ];
        // A silent YAML miss would make the marker checks vacuous.
        foreach ($expect as $id => $pair) {
            self::assertNotEmpty($pair[1], "expect: list for {$id} loaded");
        }

        $guard = FingerprintGuard::fromPackage();
        foreach ($this->materials() as $mat) {
            $deploySeed = PersonaIdentity::seedFromMaterial($mat);
            foreach ($this->renderSeeds() as $renderSeed) {
                foreach ($expect as $id => $pair) {
                    [$artifact, $markers] = $pair;
                    $body = $this->render($id, $artifact, $deploySeed, $renderSeed);
                    foreach ($markers as $marker) {
                        self::assertStringContainsString($marker, $body, "m=[{$mat}] {$id} marker '{$marker}' survives");
                    }
                    self::assertSame([], $guard->scan($body), "m=[{$mat}] {$id} rendered body is fingerprint-clean");
                    foreach ($this->headers($id, $artifact) as $value) {
                        self::assertSame([], $guard->scan($value), "m=[{$mat}] {$id} rendered header is fingerprint-clean");
                    }
                }
            }
        }
    }

    // --- helpers -----------------------------------------------------------------------------------

    /** True if $s discloses a served demo brand: any-case example.com, or the literal @acme scope. */
    private function hasDemoBrand(string $s): bool
    {
        return stripos($s, 'example.com') !== false || strpos($s, '@acme') !== false;
    }

    /**
     * Every served response leaf of a compiled rule: response body(ies) plus header values, wherever
     * they nest (top-level route response, attack response, branch/variant case responses). Detection
     * selectors (match/when/lit/regex/contains) and exploit-confirmation markers (expect) are NOT
     * served, so they are skipped by construction — the sweep is a law for what the honeypot SENDS.
     *
     * @param array<mixed> $rule
     *
     * @return list<string>
     */
    private function servedLeaves(array $rule): array
    {
        $out = [];
        self::collectResponseLeaves($rule, $out);

        return $out;
    }

    /**
     * @param mixed         $node
     * @param list<string> $out
     */
    private static function collectResponseLeaves($node, array &$out): void
    {
        if (!is_array($node)) {
            return;
        }
        foreach ($node as $key => $val) {
            if ($key === 'body' && is_string($val)) {
                $out[] = $val;
            } elseif ($key === 'headers' && is_array($val)) {
                foreach ($val as $headerValue) {
                    if (is_string($headerValue)) {
                        $out[] = $headerValue;
                    }
                }
            } elseif (is_array($val)) {
                self::collectResponseLeaves($val, $out);
            }
        }
    }

    /** The compiled rule with $id from $artifact, or null. */
    private function rule(string $id, string $artifact): ?array
    {
        foreach ((array) (require $artifact) as $rule) {
            if (is_array($rule) && ($rule['id'] ?? null) === $id) {
                return $rule;
            }
        }

        return null;
    }

    /** The template body of $id — top-level for routes, response.body for attack rules. */
    private function bodyOf(string $id, string $artifact): string
    {
        $rule = $this->rule($id, $artifact);
        self::assertNotNull($rule, "rule '{$id}' is not present in the compiled artifact");
        if (isset($rule['body']) && is_string($rule['body'])) {
            return $rule['body'];
        }

        return (string) ($rule['response']['body'] ?? '');
    }

    /** The header values of $id — top-level for routes, response.headers for attack rules. */
    private function headers(string $id, string $artifact): array
    {
        $rule = (array) $this->rule($id, $artifact);
        $headers = $rule['headers'] ?? ($rule['response']['headers'] ?? []);

        return array_values(array_map('strval', (array) $headers));
    }

    /** Render $id's body through the render path with the deploy seed wired (as prod does). */
    private function render(string $id, string $artifact, int $deploySeed, int $renderSeed, array $captures = []): string
    {
        return (new DirectiveRenderer($deploySeed))->render($this->bodyOf($id, $artifact), $captures, $renderSeed);
    }

    /** The first line of a body (the Citrix JSON leak line sits before the fabricated memory blob). */
    private function firstLine(string $body): string
    {
        $nl = strpos($body, "\n");

        return $nl === false ? $body : substr($body, 0, $nl);
    }

    /** The expect: list of a template YAML, parsed the same way the compiler/gate collect markers. */
    private function expectOf(string $relPath): array
    {
        $doc = Yaml::parseFile(self::TPL . '/' . $relPath);
        $markers = [];
        foreach ((array) ($doc['expect'] ?? []) as $marker) {
            $markers[] = (string) $marker;
        }

        return $markers;
    }
}
