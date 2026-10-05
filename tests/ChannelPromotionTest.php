<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Rules\ChannelPromotion;
use Funnypot\Core\Rules\KeyRing;
use Funnypot\Core\Rules\RulesUpdateException;
use Funnypot\Core\Rules\SignatureVerifier;
use Funnypot\Core\SchemaVersion;
use Funnypot\Core\Tests\Support\ReleaseFactory;
use PHPUnit\Framework\TestCase;

/**
 * FP-0331: publish ≠ promote. ChannelPromotion is the pure, injectable core of the rules publisher's
 * channel-pointer handling — it VERIFIES a base channels.json against a channels-role key before
 * trusting it, then moves exactly one pointer while carrying `revoked` and the untouched pointer
 * forward. These tests exercise it with ephemeral role keypairs (via ReleaseFactory) and byte-distinct
 * base channel docs, so the whole safety contract is asserted with no secrets and no real release.
 */
final class ChannelPromotionTest extends TestCase
{
    private function factory(): ReleaseFactory
    {
        return new ReleaseFactory(sys_get_temp_dir() . '/fp0331-' . uniqid('', true));
    }

    private function promoter(ReleaseFactory $f): ChannelPromotion
    {
        return new ChannelPromotion($f->verifier());
    }

    /** @param array<string,mixed> $channels @return array{0:string,1:string} [json, raw detached sig] */
    private function signedBase(ReleaseFactory $f, array $channels): array
    {
        $json = (string) json_encode($channels, JSON_UNESCAPED_SLASHES);

        return [$json, $f->sign(SignatureVerifier::CONTEXT_CHANNELS, $json, 'channels')];
    }

    /** A plausible base channels doc with the given pointers/revocations. */
    private function channelsDoc(string $latest, string $stable, array $revoked = []): array
    {
        return [
            'schema' => SchemaVersion::RELEASE_CURRENT,
            'generated_at' => gmdate('c', 1600000000),
            'expires' => gmdate('c', 1600000000 + 7 * 86400),
            'latest' => $latest,
            'stable' => $stable,
            'revoked' => $revoked,
        ];
    }

    // --- carryForward: pointer movement + carry-forward -----------------------------------------

    public function test_promote_latest_moves_only_latest_preserving_stable_and_revoked(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v1', 'v0', ['vbad1', 'vbad2']));
        $now = 1700000000;

        $new = $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', $now, 7);

        self::assertSame('v2', $new['latest'], 'latest advances to the new version');
        self::assertSame('v0', $new['stable'], 'stable is carried forward untouched');
        self::assertSame(['vbad1', 'vbad2'], $new['revoked'], 'revoked is carried verbatim');
        self::assertSame(SchemaVersion::RELEASE_CURRENT, $new['schema'], 'schema unchanged');
        self::assertSame($now, strtotime($new['generated_at']), 'generated_at re-stamped to now');
        self::assertSame($now + 7 * 86400, strtotime($new['expires']), 'expires re-stamped to now+ttl');
    }

    public function test_promote_stable_ok_when_base_latest_equals_target(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v2', 'v1'));

        $new = $this->promoter($f)->carryForward($json, $sig, 'stable', 'v2', 1700000000, 7);

        self::assertSame('v2', $new['stable']);
        self::assertSame('v2', $new['latest'], 'latest unchanged (already v2)');
    }

    public function test_promote_stable_refused_when_ahead_of_latest(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v2', 'v1'));

        $this->expectException(RulesUpdateException::class);
        $this->expectExceptionMessageMatches('/stable.*latest|ahead/i');
        $this->promoter($f)->carryForward($json, $sig, 'stable', 'v3', 1700000000, 7);
    }

    public function test_promote_target_in_revoked_is_refused(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v1', 'v0', ['v2']));

        try {
            $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7);
            self::fail('promoting to a revoked version must throw');
        } catch (RulesUpdateException $e) {
            self::assertSame(RulesUpdateException::REASON_DOWNGRADE, $e->reason());
        }
    }

    public function test_revoked_list_carried_verbatim_across_promotion(): void
    {
        $f = $this->factory();
        $revoked = ['va', 'vb', 'vc'];
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v1', 'v1', $revoked));

        $new = $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7);
        self::assertSame($revoked, $new['revoked'], 'no resurrection, no reorder, no drop');
    }

    public function test_unknown_base_fields_are_preserved(): void
    {
        $f = $this->factory();
        $doc = $this->channelsDoc('v1', 'v0');
        $doc['note'] = 'future-field';           // a field this tool does not know about
        $doc['channels_meta'] = ['x' => 1];
        [$json, $sig] = $this->signedBase($f, $doc);

        $new = $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7);
        self::assertSame('future-field', $new['note'], 'unknown scalar field carried forward');
        self::assertSame(['x' => 1], $new['channels_meta'], 'unknown nested field carried forward');
    }

    public function test_stale_doc_but_valid_key_succeeds_and_restamps(): void
    {
        // Doc freshness (expires) is a CONSUMER concern; the publisher only needs the signing KEY to be
        // valid. A base whose `expires` is in the past must still promote (re-stamping freshness is the
        // whole point of a scheduled re-sign) — nobody should "fix" this into a rejection.
        $f = $this->factory();
        $doc = $this->channelsDoc('v1', 'v0');
        $doc['generated_at'] = gmdate('c', 1500000000);
        $doc['expires'] = gmdate('c', 1500000000 + 7 * 86400); // long past
        [$json, $sig] = $this->signedBase($f, $doc);
        $now = 1700000000;

        $new = $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', $now, 7);
        self::assertSame($now + 7 * 86400, strtotime($new['expires']), 're-stamped forward');
    }

    // --- carryForward: fail-closed verification -------------------------------------------------

    public function test_forged_base_signature_throws_and_never_resets(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v1', 'v0', ['vbad']));
        $sig[10] = $sig[10] === 'A' ? 'B' : 'A'; // flip a byte

        try {
            $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7);
            self::fail('a forged base signature must throw — never silently return a reset doc');
        } catch (RulesUpdateException $e) {
            self::assertContains($e->reason(), [
                RulesUpdateException::REASON_BAD_SIGNATURE,
                RulesUpdateException::REASON_NO_TRUSTED_KEY,
            ]);
        }
    }

    public function test_base_signed_with_wrong_role_throws(): void
    {
        // Base signed by the RELEASE key but verified as a channels pointer → no trusted channels key.
        $f = $this->factory();
        $json = (string) json_encode($this->channelsDoc('v1', 'v0'), JSON_UNESCAPED_SLASHES);
        $sig = $f->sign(SignatureVerifier::CONTEXT_CHANNELS, $json, 'release');

        $this->expectException(RulesUpdateException::class);
        $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7);
    }

    public function test_channels_key_outside_its_validity_window_throws(): void
    {
        // A genuinely windowed key needs its own keypair (ReleaseFactory's keys are open-ended).
        $kp = sodium_crypto_sign_keypair();
        $sk = sodium_crypto_sign_secretkey($kp);
        $pk = sodium_crypto_sign_publickey($kp);
        $ring = new KeyRing([[
            'key_id' => 'expired-channels',
            'public_key' => base64_encode($pk),
            'valid_from' => '2000-01-01',
            'valid_until' => '2001-01-01', // long expired relative to $now below
            'roles' => ['channels'],
        ]]);
        $promoter = new ChannelPromotion(new SignatureVerifier($ring));

        $json = (string) json_encode($this->channelsDoc('v1', 'v0'), JSON_UNESCAPED_SLASHES);
        $sig = sodium_crypto_sign_detached(SignatureVerifier::CONTEXT_CHANNELS . $json, $sk);

        $this->expectException(RulesUpdateException::class);
        $promoter->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7);
    }

    public function test_base_sig_accepted_raw_base64_or_hex(): void
    {
        // The publisher emits a raw 64-byte detached sig; a consumer-side normaliser also accepts
        // base64/hex. Never trim (an ed25519 sig can start/end with a whitespace-valued byte).
        $f = $this->factory();
        [$json, $raw] = $this->signedBase($f, $this->channelsDoc('v1', 'v0'));
        $p = $this->promoter($f);

        $a = $p->carryForward($json, $raw, 'latest', 'v2', 1700000000, 7);
        $b = $p->carryForward($json, base64_encode($raw), 'latest', 'v2', 1700000000, 7);
        $c = $p->carryForward($json, bin2hex($raw), 'latest', 'v2', 1700000000, 7);
        self::assertSame($a['latest'], $b['latest']);
        self::assertSame($a['latest'], $c['latest']);
    }

    public function test_unparseable_base_json_throws(): void
    {
        $f = $this->factory();
        $json = 'not-json{';
        $sig = $f->sign(SignatureVerifier::CONTEXT_CHANNELS, $json, 'channels');

        $this->expectException(RulesUpdateException::class);
        $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7);
    }

    public function test_unknown_promote_target_throws(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v1', 'v0'));

        $this->expectException(RulesUpdateException::class);
        $this->promoter($f)->carryForward($json, $sig, 'beta', 'v2', 1700000000, 7);
    }

    // --- carryForward: compare-and-swap (concurrency guard) -------------------------------------

    public function test_expect_latest_mismatch_throws(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v1', 'v0'));

        $this->expectException(RulesUpdateException::class);
        // base latest is v1, but caller expected v9 → the base changed under us; refuse.
        $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7, 'v9', null);
    }

    public function test_expect_latest_match_ok(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedBase($f, $this->channelsDoc('v1', 'v0'));

        $new = $this->promoter($f)->carryForward($json, $sig, 'latest', 'v2', 1700000000, 7, 'v1', 'v0');
        self::assertSame('v2', $new['latest']);
    }

    // --- verifyManifestVersion (promote-only guard) ---------------------------------------------

    /** @return array{0:string,1:string} [manifestJson, raw sig] signed by the release key */
    private function signedManifest(ReleaseFactory $f, string $version, string $role = 'release'): array
    {
        $manifest = ['schema' => SchemaVersion::RELEASE_CURRENT, 'version' => $version, 'version_seq' => 1];
        $json = (string) json_encode($manifest, JSON_UNESCAPED_SLASHES);

        return [$json, $f->sign(SignatureVerifier::CONTEXT_MANIFEST, $json, $role)];
    }

    public function test_verify_manifest_version_ok(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedManifest($f, 'v2');
        $this->promoter($f)->verifyManifestVersion($json, $sig, 'v2', 1700000000);
        $this->addToAssertionCount(1); // no throw == pass
    }

    public function test_verify_manifest_version_mismatch_throws(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedManifest($f, 'v2');

        try {
            $this->promoter($f)->verifyManifestVersion($json, $sig, 'v3', 1700000000);
            self::fail('a version mismatch must throw');
        } catch (RulesUpdateException $e) {
            self::assertSame(RulesUpdateException::REASON_BAD_MANIFEST, $e->reason());
        }
    }

    public function test_verify_manifest_flipped_sig_throws(): void
    {
        $f = $this->factory();
        [$json, $sig] = $this->signedManifest($f, 'v2');
        $sig[5] = $sig[5] === 'A' ? 'B' : 'A';

        $this->expectException(RulesUpdateException::class);
        $this->promoter($f)->verifyManifestVersion($json, $sig, 'v2', 1700000000);
    }

    public function test_verify_manifest_wrong_role_throws(): void
    {
        // Manifest signed by the CHANNELS key but verified as a release manifest → no trusted key.
        $f = $this->factory();
        [$json, $sig] = $this->signedManifest($f, 'v2', 'channels');

        $this->expectException(RulesUpdateException::class);
        $this->promoter($f)->verifyManifestVersion($json, $sig, 'v2', 1700000000);
    }

    // --- planWrites (which files a mode writes) -------------------------------------------------

    public function test_plan_writes_publish_none_writes_artifacts_only(): void
    {
        $plan = ChannelPromotion::planWrites(false, 'none', false);
        self::assertTrue($plan['artifacts'], 'publish writes the tarball+manifest');
        self::assertFalse($plan['channels'], 'promote=none writes NO channels.json (the fix)');
    }

    public function test_plan_writes_publish_promote_writes_channels(): void
    {
        $plan = ChannelPromotion::planWrites(false, 'latest', false);
        self::assertTrue($plan['artifacts']);
        self::assertTrue($plan['channels']);
    }

    public function test_plan_writes_bootstrap_writes_channels(): void
    {
        $plan = ChannelPromotion::planWrites(false, 'none', true);
        self::assertTrue($plan['channels'], 'explicit bootstrap writes a fresh channels doc');
    }

    public function test_plan_writes_promote_only_writes_channels_not_artifacts(): void
    {
        $plan = ChannelPromotion::planWrites(true, 'latest', false);
        self::assertFalse($plan['artifacts'], 'promote-only never repackages');
        self::assertTrue($plan['channels']);
    }
}
