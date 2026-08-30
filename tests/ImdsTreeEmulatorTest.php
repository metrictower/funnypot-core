<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The coherent AWS IMDS tree (attack/91-imds-base.yaml + 89-imds-identity-doc.yaml, with the STS
 * credential leaf still 90-imds.yaml). Pins the two invariants the tree exists for:
 *   - NO partial tell: every child the category listing advertises resolves to a non-404 body, and
 *     recursively every child a sub-directory lists resolves too.
 *   - internal coherence: the instance-identity document never contradicts the meta-data leaves,
 *     and the iam role-name listing / STS-credential split is both correct and inert.
 */
final class ImdsTreeEmulatorTest extends TestCase
{
    private const ATTACK_COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    /** A fixed persona seed so {{persona.*}} (region/AZ) resolves deterministically. */
    private const PERSONA_SEED = 4242;

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::ATTACK_COMPILED, [], self::PERSONA_SEED);
    }

    /** The rendered body for a GET, or null when nothing matched (an app 404). */
    private function body(string $path): ?string
    {
        $r = $this->emulator()->emulate(new RequestContext('GET', $path), 777);

        return $r === null ? null : $r->body;
    }

    private function get(string $path): \Funnypot\Core\SynthesizedResponse
    {
        $r = $this->emulator()->emulate(new RequestContext('GET', $path), 777);
        self::assertNotNull($r, "IMDS path unexpectedly 404'd: {$path}");

        return $r;
    }

    // --- no partial tell: the whole walked tree resolves ------------------------------------------

    /**
     * Walk the tree exactly as an SSRF scanner would: read a directory listing, follow every entry,
     * recurse into the ones ending in '/'. Asserts NONE resolve to a 404, so there is no half-served
     * leaf. Also proves the iam split chains: security-credentials/ lists a role name that, when
     * requested, resolves (to the STS blob 90-imds serves).
     */
    public function test_every_advertised_child_resolves_non_404(): void
    {
        $seen = [];
        $leafCount = 0;
        $this->walk('/latest/meta-data/', $seen, $leafCount, 0);
        // A sanity floor: the walk must actually have exercised a real spread of leaves, not bailed
        // early. The tree has well over a dozen reachable leaves.
        self::assertGreaterThan(15, $leafCount, 'the recursive walk covered too few leaves — it bailed early');
    }

    /**
     * @param array<string,true> $seen guards against a cycle (there is none, but keep the walk total)
     */
    private function walk(string $dir, array &$seen, int &$leafCount, int $depth): void
    {
        self::assertLessThan(12, $depth, "IMDS tree deeper than expected at {$dir}");
        if (isset($seen[$dir])) {
            return;
        }
        $seen[$dir] = true;

        $listing = $this->body($dir);
        self::assertNotNull($listing, "IMDS directory 404'd: {$dir}");

        foreach (preg_split('/\r?\n/', trim($listing)) ?: [] as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            $childPath = $dir . $entry;
            if (substr($entry, -1) === '/') {
                $this->walk($childPath, $seen, $leafCount, $depth + 1);
                continue;
            }
            // A leaf (no trailing slash): must resolve to a non-404.
            self::assertNotNull($this->body($childPath), "IMDS leaf 404'd: {$childPath}");
            $leafCount++;
        }
    }

    /** The base category listing is served for the bare root as plain text, listing dirs with '/'. */
    public function test_base_listing_is_plaintext_and_lists_dirs_with_trailing_slash(): void
    {
        foreach (['/latest/meta-data', '/latest/meta-data/'] as $path) {
            $r = $this->get($path);
            self::assertSame(200, $r->status, $path);
            self::assertSame('text/plain', $r->headers['Content-Type'] ?? null, $path);
            self::assertStringContainsString('instance-id', $r->body, $path);
            self::assertStringContainsString('placement/', $r->body, $path);
        }
    }

    // --- internal coherence: the identity document agrees with the leaves ------------------------

    public function test_identity_document_is_coherent_with_the_meta_data_leaves(): void
    {
        $doc = json_decode($this->get('/latest/dynamic/instance-identity/document')->body, true);
        self::assertIsArray($doc, 'the identity document must be valid JSON');

        self::assertSame(
            trim($this->get('/latest/meta-data/instance-id')->body),
            $doc['instanceId'] ?? null,
            'document.instanceId must equal the /instance-id leaf'
        );
        self::assertSame(
            trim($this->get('/latest/meta-data/ami-id')->body),
            $doc['imageId'] ?? null,
            'document.imageId must equal the /ami-id leaf'
        );
        self::assertSame(
            trim($this->get('/latest/meta-data/local-ipv4')->body),
            $doc['privateIp'] ?? null,
            'document.privateIp must equal the /local-ipv4 leaf'
        );
        self::assertSame(
            trim($this->get('/latest/meta-data/placement/region')->body),
            $doc['region'] ?? null,
            'document.region must equal the /placement/region leaf'
        );
        self::assertSame(
            trim($this->get('/latest/meta-data/placement/availability-zone')->body),
            $doc['availabilityZone'] ?? null,
            'document.availabilityZone must equal the /placement/availability-zone leaf'
        );
        // The region is derivable from the AZ: the AZ is the region plus a single letter.
        self::assertStringStartsWith(
            (string) $doc['region'],
            (string) $doc['availabilityZone'],
            'the region must be a prefix of the AZ'
        );
        // The account id recurs on the network owner-id leaf.
        self::assertSame(
            trim($this->get('/latest/meta-data/network/interfaces/macs/06:00:00:00:00:00/owner-id')->body),
            $doc['accountId'] ?? null,
            'document.accountId must equal the network owner-id leaf'
        );
    }

    /** The hostname embeds the same private-IP octets the /local-ipv4 leaf reports. */
    public function test_hostname_embeds_the_private_ip(): void
    {
        $ip = trim($this->get('/latest/meta-data/local-ipv4')->body);
        $dashed = str_replace('.', '-', $ip);
        self::assertStringContainsString('ip-' . $dashed . '.', $this->get('/latest/meta-data/hostname')->body);
    }

    // --- the iam split: role-name listing vs STS credential blob ---------------------------------

    public function test_iam_role_listing_returns_a_plausible_role_name_not_json(): void
    {
        foreach (['/latest/meta-data/iam/security-credentials/', '/latest/meta-data/iam/security-credentials'] as $path) {
            $role = trim($this->get($path)->body);
            self::assertNotSame('', $role, $path);
            self::assertStringNotContainsString('{', $role, "the listing is a role NAME, never the JSON blob: {$path}");
            self::assertStringNotContainsString('AccessKeyId', $role, $path);
            // A plausible IAM role slug.
            self::assertMatchesRegularExpression('/^[A-Za-z0-9_+=,.@-]{1,64}$/', $role, $path);
        }
    }

    public function test_requesting_the_listed_role_returns_inert_sts_credentials(): void
    {
        // Walk the split as an attacker would: read the role name, then request it.
        $role = trim($this->get('/latest/meta-data/iam/security-credentials/')->body);
        $creds = json_decode($this->get('/latest/meta-data/iam/security-credentials/' . $role)->body, true);
        self::assertIsArray($creds, 'the credential leaf must be valid JSON');

        foreach (['Code', 'LastUpdated', 'Type', 'AccessKeyId', 'SecretAccessKey', 'Token', 'Expiration'] as $field) {
            self::assertArrayHasKey($field, $creds, "STS blob missing '{$field}'");
        }
        self::assertSame('Success', $creds['Code']);
        self::assertSame('AWS-HMAC', $creds['Type']);

        // INERT: a temporary-STS shape (ASIA prefix), never a working AWS credential. It must NOT be
        // a long-lived AKIA key, and the body must carry no real-secret marker beyond the fake shape.
        self::assertStringStartsWith('ASIA', (string) $creds['AccessKeyId'], 'temp STS keys are ASIA-prefixed');
        self::assertStringStartsNotWith('AKIA', (string) $creds['AccessKeyId'], 'must not look like a long-lived key');
        self::assertMatchesRegularExpression('/^ASIA[0-9A-F]{16}$/', (string) $creds['AccessKeyId'], 'inert ASIA key shape');
        self::assertNotSame('', (string) $creds['SecretAccessKey']);
        self::assertNotSame('', (string) $creds['Token']);
    }

    /** The deeper credential leaf stays 90-imds's job — the tree rule must not shadow it. */
    public function test_credential_leaf_is_served_by_the_deeper_rule(): void
    {
        $r = $this->get('/latest/meta-data/iam/security-credentials/some-role');
        self::assertSame(['attack-cloud-imds'], $r->satisfies->templateIds());
    }
}
