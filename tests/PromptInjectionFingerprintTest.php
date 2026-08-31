<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Response\InjectionPayloads;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;

/**
 * FP-0239 — the ONLY coverage of the runtime prompt-injection payload text. The CI fingerprint gate
 * (scripts/ci/check-fingerprint-safety.php) scans the COMPILED route artifact's body/headers/
 * set_cookie/taunt.open|close|key — but the payload lives in PHP (InjectionPayloads), never compiled,
 * so the artifact gate cannot reach it. This test closes that gap two ways:
 *   1. no payload line (or a fully-rendered sample block) carries an upstream-detector signature
 *      (spec invariant 6 — FingerprintGuard::scan() === []);
 *   2. every payload is INERT + DEFENSIVE-ONLY: misdirection + a self-beacon GET, and nothing else —
 *      no destructive/shell/SQL token, no third-party host, no SSRF/RFC1918/metadata lure, no literal
 *      URL in the constants (spec invariants 1/2/3 — the safety bright line, made falsifiable).
 */
final class PromptInjectionFingerprintTest extends TestCase
{
    private function guard(): FingerprintGuard
    {
        return FingerprintGuard::fromPackage();
    }

    /** Every payload line the feature can ever emit (misdirection + the beacon template). */
    private function allPayloadLines(): array
    {
        return array_merge(InjectionPayloads::MISDIRECTION, [InjectionPayloads::BEACON_TEMPLATE]);
    }

    /** A fully-rendered sample block in each comment mode, beacon substituted, as actually served. */
    private function renderedSamples(): array
    {
        $set = RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');
        $canary = ['beacon' => 'https://beacon.example.test/confirm?t=' . str_repeat('a', 40)];
        $emu = new RouteTemplateEmulator($set, new DirectiveRenderer(7), true, $canary);
        $index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';

        $out = [];
        foreach (['GET /readme.html', 'GET /phpmyadmin/README', 'GET /.well-known/ai-plugin.json'] as $route) {
            $bundle = $index['routes'][$route]['b'][0];
            $out[$route] = $emu->render($bundle, Style::REALISTIC, 7)->body;
        }

        return $out;
    }

    public function test_no_payload_carries_a_detector_signature(): void
    {
        $guard = $this->guard();
        foreach ($this->allPayloadLines() as $line) {
            self::assertSame([], $guard->scan($line), "payload line carries a detector signature: {$line}");
        }
        foreach ($this->renderedSamples() as $route => $body) {
            self::assertSame([], $guard->scan($body), "rendered injection block leaks a signature ({$route})");
        }
    }

    public function test_payloads_are_inert_no_forbidden_directive(): void
    {
        // FORBIDDEN: destructive/side-effecting commands, exfil verbs, network fetch tools, SSRF/RFC1918/
        // metadata hosts. The payload requests at most a GET on the operator self-beacon — nothing else.
        $forbidden = '~\b('
            . 'rm\s+-rf|DROP\s+TABLE|TRUNCATE|DELETE\s+FROM|shutdown|reboot|mkfs|'
            . 'curl|wget|fetch\(|nc\s|netcat|bash|/bin/sh|powershell|'
            . 'exec|eval|system|passthru|shell_exec|base64_decode|'
            . 'POST|PUT|DELETE\s|'
            . 'exfiltrate|env|/etc/passwd|id_rsa|AKIA|BEGIN\s+PRIVATE|'
            . '169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost|'
            . '10\.\d+\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.'
            . ')\b~i';

        foreach ($this->allPayloadLines() as $line) {
            self::assertSame(0, preg_match($forbidden, $line), "payload line contains a forbidden directive: {$line}");
        }

        // The constants carry NO literal URL — the only URL is the injected self-beacon (via canary).
        foreach ($this->allPayloadLines() as $line) {
            self::assertStringNotContainsString('http://', $line, "no literal URL in the payload constants: {$line}");
            self::assertStringNotContainsString('https://', $line, "no literal URL in the payload constants: {$line}");
        }
        self::assertStringContainsString('{{canary.beacon}}', InjectionPayloads::BEACON_TEMPLATE);
    }

    public function test_rendered_block_only_url_is_the_operator_beacon(): void
    {
        // The ONLY http(s) URL the feature ever emits is the configured operator beacon base — no
        // third-party host, no metadata endpoint (spec invariants 2/3). Render each payload line with a
        // known beacon canary and assert every URL host is the beacon; the misdirection lines carry none.
        $renderer = new DirectiveRenderer(7);
        $canary = ['beacon' => 'https://beacon.example.test/confirm?t=deadbeef'];

        foreach (InjectionPayloads::MISDIRECTION as $line) {
            $rendered = $renderer->render($line, [], 7, $canary);
            self::assertSame(0, preg_match('~https?://~', $rendered), "misdirection line must carry no URL: {$line}");
        }

        $beacon = $renderer->render(InjectionPayloads::BEACON_TEMPLATE, [], 7, $canary);
        self::assertSame(1, preg_match_all('~https?://([^\s"/?)]+)~', $beacon, $m), 'beacon line renders exactly one URL');
        self::assertSame('beacon.example.test', $m[1][0], 'the only URL host is the operator beacon');
        self::assertStringNotContainsString('169.254.169.254', $beacon);
    }
}
