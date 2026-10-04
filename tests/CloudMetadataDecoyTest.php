<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0471: the multi-cloud metadata honeytrap — GCP (85), Azure (86), DigitalOcean (87), AWS IMDSv2 (92),
 * extending the existing AWS IMDS surface (89/90/91). Model A: the honeypot IS the metadata endpoint (hit
 * at the path). Every credential is an inert {{fake.*}} honeytoken. Also asserts the coherence fix: 90 no
 * longer serves the AWS STS blob on GCP/Azure paths.
 */
final class CloudMetadataDecoyTest extends TestCase
{
    /** @var array<string,mixed> */
    private static function index(): array
    {
        return require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    }

    /** @param string[] $ignore */
    private function engine(string $seed = 'fixed', string $ceiling = 'high', array $ignore = []): Honeypot
    {
        // Default ceiling is 'high' — the real default (Config.php) that the wordpress/laravel embedders
        // run. The cloud surfaces are severity: high, so they MUST serve here (not only at prod critical).
        $cfg = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'fixed'; },
            'coherent',
            Style::REALISTIC,
            $ceiling,
            65536,
            0,
            0,
            false,
            null,
            null,
            null,
            $seed
        );
        $cfg->attackEmulation = true;
        if ($ignore !== []) {
            $cfg->ignoreTemplates = $ignore;
        }

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    private function resp(string $method, string $path, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext($method, $path, '', [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    // ---- GCP (85) ------------------------------------------------------------------------------

    public function test_gcp_v1_tree_serves_with_metadata_flavor_header(): void
    {
        $r = $this->resp('GET', '/computeMetadata/v1/');
        self::assertSame(200, $r->status ?? null);
        self::assertSame('Google', $r->headers['Metadata-Flavor'] ?? null, 'GCP must emit Metadata-Flavor: Google');
        self::assertStringContainsString('instance/', $this->body($r));
        self::assertStringContainsString('project/', $this->body($r));
    }

    public function test_gcp_v1beta1_headerless_token_is_canary_oauth(): void
    {
        $r = $this->resp('GET', '/computeMetadata/v1beta1/instance/service-accounts/default/token');
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('ya29.', $this->body($r), 'GCP canary OAuth2 access token');
        self::assertStringContainsString('"token_type":"Bearer"', $this->body($r));
    }

    public function test_gcp_project_id_is_coherent_text(): void
    {
        $r = $this->resp('GET', '/computeMetadata/v1/project/project-id');
        self::assertSame(200, $r->status ?? null);
        self::assertStringNotContainsString('AccessKeyId', $this->body($r));
    }

    // ---- Azure (86) ----------------------------------------------------------------------------

    public function test_azure_instance_serves_compute_network_json(): void
    {
        $r = $this->resp('GET', '/metadata/instance');
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('azEnvironment', $this->body($r));
        self::assertStringContainsString('subscriptionId', $this->body($r));
        self::assertStringContainsString('"network"', $this->body($r));
    }

    public function test_azure_identity_token_is_canary_bearer(): void
    {
        $r = $this->resp('GET', '/metadata/identity/oauth2/token');
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('"token_type":"Bearer"', $this->body($r));
        self::assertStringContainsString('management.azure.com', $this->body($r));
    }

    // ---- DigitalOcean (87) ---------------------------------------------------------------------

    public function test_digitalocean_droplet_json(): void
    {
        $r = $this->resp('GET', '/metadata/v1.json');
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('droplet_id', $this->body($r));
        self::assertStringContainsString('"region"', $this->body($r));
    }

    // ---- AWS IMDSv2 (92) -----------------------------------------------------------------------

    public function test_aws_imdsv2_put_token(): void
    {
        $r = $this->resp('PUT', '/latest/api/token');
        self::assertSame(200, $r->status ?? null);
        self::assertNotSame('', trim($this->body($r)), 'IMDSv2 PUT must return a token');
        self::assertStringNotContainsString('#!/bin/bash', $this->body($r), 'token path must not serve the user-data body');
    }

    public function test_aws_user_data_bait(): void
    {
        $r = $this->resp('GET', '/latest/user-data');
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('DB_HOST', $this->body($r));
    }

    // ---- Regression: AWS surface still intact (89/90/91) ---------------------------------------

    public function test_aws_sts_credential_leaf_still_served(): void
    {
        $r = $this->resp('GET', '/latest/meta-data/iam/security-credentials/myrole');
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('AccessKeyId', $this->body($r));
        self::assertStringContainsString('SecretAccessKey', $this->body($r));
    }

    public function test_aws_instance_identity_document_still_served(): void
    {
        $r = $this->resp('GET', '/latest/dynamic/instance-identity/document');
        self::assertSame(200, $r->status ?? null);
        self::assertStringContainsString('accountId', $this->body($r));
    }

    // ---- Coherence fix: 90 no longer serves AWS STS on GCP/Azure paths -------------------------

    public function test_gcp_and_azure_paths_do_not_leak_aws_credentials(): void
    {
        foreach (['/computeMetadata/v1/', '/computeMetadata/v1/instance/', '/metadata/instance'] as $p) {
            self::assertStringNotContainsString('AccessKeyId', $this->body($this->resp('GET', $p)), "{$p} must not serve the AWS STS blob");
        }
    }

    // ---- Per-cloud coherence across seeds + canary presence ------------------------------------

    public function test_canary_tokens_vary_per_seed(): void
    {
        $a = $this->body($this->resp('GET', '/computeMetadata/v1/instance/service-accounts/default/token', 'seedA'));
        $b = $this->body($this->resp('GET', '/computeMetadata/v1/instance/service-accounts/default/token', 'seedB'));
        self::assertNotSame('', $a);
        self::assertNotSame($a, $b, 'honeytokens must vary per deploy seed');
    }

    // ---- B1 regression pin: the surfaces serve at the DEFAULT ('high') ceiling -------------------

    public function test_surfaces_serve_at_default_high_ceiling(): void
    {
        // engine() already uses ceiling 'high'; be explicit here so a future severity bump is caught.
        foreach (['/computeMetadata/v1/', '/computeMetadata/v1/instance/service-accounts/default/token',
            '/metadata/instance', '/metadata/v1.json', '/latest/user-data'] as $p) {
            $r = $this->engine('fixed', 'high')->respond(new RequestContext('GET', $p, '', [], null, 'x.test'));
            self::assertNotNull($r, "{$p} must serve at the default high ceiling");
            self::assertSame(200, $r->status, "{$p} must be 200 at high ceiling");
        }
    }

    // ---- S1: unknown GCP key -> 404, walk terminates (no self-similar loop) ----------------------

    public function test_gcp_unknown_key_returns_404_not_root_listing(): void
    {
        foreach (['/computeMetadata/v1/bogus/unknown',
            '/computeMetadata/v1/instance/service-accounts/default/foo/bar/baz'] as $p) {
            $r = $this->resp('GET', $p);
            self::assertSame(404, $r->status ?? null, "{$p} must 404");
            self::assertStringNotContainsString('instance/', $this->body($r), "{$p} must not fall back to the root listing (loop)");
        }
    }

    // ---- S3: no-shadow — GCP/Azure are owned by 85/86, not 90 (pin the narrowing) ---------------

    public function test_90_match_regex_is_narrowed_to_aws_only(): void
    {
        // Structural proof of the coherence fix: 90 (attack-cloud-imds) no longer matches the GCP/Azure
        // paths, so it can never serve the AWS STS blob there regardless of rule precedence.
        $rule = \Funnypot\Core\Template\TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php')
            ->ruleById('attack-cloud-imds');
        self::assertNotNull($rule, 'attack-cloud-imds must exist');
        $regexes = implode(' ', array_map(static function (array $c): string {
            return (string) ($c['regex'] ?? '');
        }, (array) ($rule['match'] ?? [])));
        self::assertStringNotContainsString('computeMetadata', $regexes, '90 must not match the GCP path (owned by 85)');
        self::assertStringNotContainsString('metadata/instance', $regexes, '90 must not match the Azure path (owned by 86)');
        self::assertStringContainsString('security-credentials', $regexes, '90 still owns the AWS STS leaf');
    }

    // ---- S3: JSON leaves are valid JSON ---------------------------------------------------------

    public function test_json_surfaces_are_valid_json(): void
    {
        foreach (['/metadata/instance', '/metadata/identity/oauth2/token', '/metadata/v1.json',
            '/computeMetadata/v1/instance/service-accounts/default/token'] as $p) {
            $b = $this->body($this->resp('GET', $p));
            self::assertNotNull(json_decode($b), "{$p} must be valid JSON: {$b}");
        }
    }

    // ---- S3: DO v1/id is coherent with the droplet_id in v1.json --------------------------------

    public function test_do_v1_id_matches_droplet_json(): void
    {
        $json = json_decode($this->body($this->resp('GET', '/metadata/v1.json')), true);
        $id = trim($this->body($this->resp('GET', '/metadata/v1/id')));
        self::assertSame((string) ($json['droplet_id'] ?? 'x'), $id, 'v1/id must equal v1.json droplet_id');
    }

    // ---- S3: determinism — same seed, same body ------------------------------------------------

    public function test_same_seed_is_deterministic(): void
    {
        self::assertSame(
            $this->body($this->resp('GET', '/metadata/instance', 'seedZ')),
            $this->body($this->resp('GET', '/metadata/instance', 'seedZ'))
        );
    }

    // ---- B2 / AC11: per-leaf fingerprint sweep across many seeds --------------------------------

    public function test_no_denylisted_digit_run_across_seeds(): void
    {
        // The bare-CRS-rule-id denylist token; a leaf that forms it would fail-closed to 404 for a whole
        // deploy. Sweep the reflective numeric leaves across many seeds.
        $leaves = ['/computeMetadata/v1/project/project-id', '/computeMetadata/v1/instance/hostname',
            '/computeMetadata/v1/instance/id', '/metadata/v1.json', '/metadata/instance'];
        for ($s = 0; $s < 1500; $s++) {
            $e = $this->engine((string) $s, 'high');
            foreach ($leaves as $p) {
                $b = $this->body($e->respond(new RequestContext('GET', $p, '', [], null, 'x.test')));
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} leaf {$p} formed a denylisted 9ddddd run: {$b}");
            }
        }
    }
}
