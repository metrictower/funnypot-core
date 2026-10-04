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

    private function engine(string $seed = 'fixed'): Honeypot
    {
        $cfg = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'fixed'; },
            'coherent',
            Style::REALISTIC,
            'critical',
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
}
