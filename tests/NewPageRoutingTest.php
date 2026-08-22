<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * Brand-new product pages (route templates with a new_page block, folded into the compiled
 * index by `funnypot merge-routes`) must route and serve like any other bundle: detect()
 * signals, respond() serves the authored body, and — the whole point — the response
 * validates against the synthesized bundle (respond() only returns non-null when it does).
 */
final class NewPageRoutingTest extends TestCase
{
    private function inverter(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',                                                        // mode
            static function (RequestContext $r): bool { return true; },       // gate
            'matched-only',                                                   // pathScope
            static function (RequestContext $r): string { return 'fixed'; },  // personaSeed
            'coherent',                                                       // personaBreadth
            'realistic'                                                       // responseStyle
        ));
    }

    /** An inverter pinned to one persona seed and response style, for per-seed bundle coverage. */
    private function seededInverter(string $seed, string $style): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            $style
        ));
    }

    /**
     * @dataProvider pages
     */
    public function test_new_page_routes_and_serves(string $path, int $status, string $marker, string $contentType): void
    {
        $inv = $this->inverter();

        self::assertTrue($inv->detect(new RequestContext('GET', $path))->matched, "{$path} must be detected");

        $resp = $inv->respond(new RequestContext('GET', $path));
        self::assertNotNull($resp, "{$path} must serve a fake");
        self::assertSame($status, $resp->status, "{$path} status");
        self::assertStringContainsString($marker, $resp->body, "{$path} must carry its marker");
        // Content-Type must match the request's file/endpoint type (a mismatch is a honeypot tell).
        self::assertSame($contentType, $resp->headers['Content-Type'] ?? null, "{$path} Content-Type");
    }

    /**
     * @return array<string, array{0:string,1:int,2:string,3:string}>
     */
    public static function pages(): array
    {
        return [
            'credentials.txt'   => ['/credentials.txt', 200, 'AWS_SECRET_ACCESS_KEY', 'text/plain; charset=utf-8'],
            'terraform.tfstate' => ['/terraform.tfstate', 200, '"terraform_version"', 'application/json'],
            'users.csv'         => ['/users.csv', 200, 'password_hash', 'text/csv; charset=utf-8'],
            'sql backup'        => ['/backup.sql', 200, 'CREATE TABLE', 'application/sql'],
            'basic-auth 401'    => ['/private/', 401, 'Authorization Required', 'text/html; charset=iso-8859-1'],
            'phpmyadmin login'  => ['/phpmyadmin/', 200, 'phpMyAdmin', 'text/html; charset=utf-8'],

            // AI-agent-config + MCP route pack. Config-file exposures (200) carry a scanner-shaped
            // key; the MCP/LLM endpoints answer with their vendor error status.
            'claude .claude.json'     => ['/.claude.json', 200, 'sk-ant-api03-', 'application/json'],
            'claude settings.json'    => ['/.claude/settings.json', 200, 'ANTHROPIC_API_KEY', 'application/json'],
            'claude desktop config'   => ['/claude_desktop_config.json', 200, 'GITHUB_PERSONAL_ACCESS_TOKEN', 'application/json'],
            'cursor mcp.json'         => ['/.cursor/mcp.json', 200, 'mcpServers', 'application/json'],
            'vscode mcp.json'         => ['/.vscode/mcp.json', 200, 'mcpServers', 'application/json'],
            'continue config.json'    => ['/.continue/config.json', 200, 'sk-ant-api03-', 'application/json'],
            'aider conf.yml'          => ['/.aider.conf.yml', 200, 'anthropic-api-key', 'text/yaml; charset=utf-8'],
            'copilot token endpoint'  => ['/copilot_internal/v2/token', 200, 'ghu_', 'application/json'],
            'openai models list'      => ['/openai/models', 200, '"object":"list"', 'application/json'],
            'mcp endpoint'            => ['/mcp', 400, 'jsonrpc', 'application/json'],
            'mcp endpoint (api)'      => ['/api/mcp', 400, 'jsonrpc', 'application/json'],
            'llm chat auth'           => ['/v1/chat', 401, 'invalid_request_error', 'application/json'],
            'llm completions auth'    => ['/v1/completions', 401, 'invalid_request_error', 'application/json'],
            'v1/models enrich'        => ['/v1/models', 200, '"owned_by":"openai"', 'application/json'],
        ];
    }

    public function test_v1_models_enrich_serves_openai_list(): void
    {
        // The corpus routes /v1/models to several OpenAI-compatible bundles; the enrich dresses the
        // selected one with a full OpenAI-shaped list. The "owned_by":"openai" marker is unique to
        // that body (minimal synth would emit only the "object":"list" body words), so its presence
        // proves the enrich rule — not a plain fallback — served the response.
        $resp = $this->inverter()->respond(new RequestContext('GET', '/v1/models'));

        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('"object":"list"', $resp->body);
        self::assertStringContainsString('"owned_by":"openai"', $resp->body);
    }

    public function test_v1_models_every_bundle_serves_valid_json(): void
    {
        // /v1/models is served by THREE candidate bundles (xinference, jan, vllm); the persona seed
        // picks one per host. The compact 260 body dresses xinference/jan, but vllm witnesses on
        // spaced-JSON regexes 260 can't carry — without 261 its minimal synth emitted an
        // unterminated, invalid-JSON fragment served as application/json (a definite tell). This
        // sweeps enough seeds to land on all three bundles and asserts EVERY one serves parseable,
        // non-empty JSON with the OpenAI list shape, in both realistic and taunt styles.
        $sawVllm = false;   // spaced-JSON vLLM body (the bundle 261 fixes)
        $sawOpenai = false; // compact OpenAI body (xinference/jan, from 260)

        foreach (['realistic', 'taunt'] as $style) {
            for ($seed = 0; $seed <= 60; $seed++) {
                $resp = $this->seededInverter((string) $seed, $style)->respond(new RequestContext('GET', '/v1/models'));

                self::assertNotNull($resp, "seed {$seed} [{$style}] must serve a fake");
                self::assertSame(200, $resp->status, "seed {$seed} [{$style}] status");
                self::assertSame('application/json', $resp->headers['Content-Type'] ?? null, "seed {$seed} [{$style}] Content-Type");
                self::assertNotSame('', $resp->body, "seed {$seed} [{$style}] body must be non-empty");

                $decoded = json_decode($resp->body, true);
                self::assertNotNull(
                    $decoded,
                    "seed {$seed} [{$style}] must be valid JSON, got: " . $resp->body
                );
                self::assertIsArray($decoded, "seed {$seed} [{$style}] JSON must be an object");
                self::assertSame('list', $decoded['object'] ?? null, "seed {$seed} [{$style}] must carry object:list");

                if (strpos($resp->body, '"owned_by" : "vllm"') !== false) {
                    $sawVllm = true;
                }
                if (strpos($resp->body, '"owned_by":"openai"') !== false) {
                    $sawOpenai = true;
                }
            }
        }

        // The sweep must actually exercise both bundle families, or it guards nothing.
        self::assertTrue($sawVllm, 'sweep must land on the vllm bundle (the one 261 fixes)');
        self::assertTrue($sawOpenai, 'sweep must land on the compact OpenAI (xinference/jan) bundle');
    }

    public function test_ai_key_is_coherent_across_surfaces(): void
    {
        // One host presents one identity: the same seed must render the SAME Anthropic key in every
        // file that carries it, so two leaked configs never contradict each other.
        $inv = $this->inverter();
        $claude = $inv->respond(new RequestContext('GET', '/.claude.json'));
        $continue = $inv->respond(new RequestContext('GET', '/.continue/config.json'));

        self::assertNotNull($claude);
        self::assertNotNull($continue);
        self::assertSame(1, preg_match('/sk-ant-api03-[A-Za-z0-9_-]{93}AA/', $claude->body, $a));
        self::assertSame(1, preg_match('/sk-ant-api03-[A-Za-z0-9_-]{93}AA/', $continue->body, $b));
        self::assertSame($a[0], $b[0], 'same seed => identical Anthropic key across surfaces');
    }

    public function test_basic_auth_emits_www_authenticate(): void
    {
        $resp = $this->inverter()->respond(new RequestContext('GET', '/private/'));

        self::assertNotNull($resp);
        self::assertArrayHasKey('Www-Authenticate', $resp->headers);
        self::assertStringContainsString('Basic realm=', $resp->headers['Www-Authenticate']);
    }

    public function test_tomcat_manager_enriches_existing_bundle(): void
    {
        $resp = $this->inverter()->respond(new RequestContext('GET', '/manager/html'));

        self::assertNotNull($resp);
        self::assertStringContainsString('Tomcat Web Application Manager', $resp->body);
    }
}
