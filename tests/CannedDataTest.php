<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * The shared canned attack markers are per-deploy seeded (FP-0277): the fleet-correlation filler
 * varies with the deploy seed while every exploit-confirmation marker survives VERBATIM at every seed.
 * These bytes are served, so they must also carry no brand tell, stay fingerprint-clean after render,
 * and every fabricated "secret" must be inert (crypt of no password, a key that decodes to nothing).
 */
final class CannedDataTest extends TestCase
{
    /** A sweep of deploy seeds every invariant is asserted across. */
    private const SEEDS = [0, 1, 5, 7, 99, 20260822, 4294967291];

    // --- #1 invariant: exploit-confirmation markers survive at EVERY seed ------------------------

    public function test_passwd_head_carries_the_root_markers_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            // The head line satisfies BOTH `root:x:0:0` and the trailing-colon `root:x:0:0:` tokens.
            self::assertStringStartsWith("root:x:0:0:root:/root:/bin/bash\n", CannedData::passwd($seed), "seed={$seed}");
        }
    }

    public function test_shadow_root_hash_is_sha512_crypt_shaped_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            $shadow = CannedData::shadow($seed);
            // $6$<salt up to 16>$<86-char hash>, crypt base64 alphabet (./0-9A-Za-z).
            self::assertSame(
                1,
                preg_match('#^root:\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}:#', $shadow),
                "seed={$seed}: root shadow entry must look like a real sha512-crypt hash"
            );
            // The aging-field layout LFI templates key on is preserved, and it is not the old all-zero hash.
            self::assertStringContainsString(':0:99999:7:::', $shadow, "seed={$seed}");
            self::assertStringNotContainsString('$000000', $shadow, "seed={$seed}");
        }
    }

    public function test_group_head_carries_the_group_marker_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            self::assertStringStartsWith("root:x:0:\n", CannedData::group($seed), "seed={$seed}");
        }
    }

    public function test_uid_head_is_preserved_and_crlf_nul_free_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            $uid = CannedData::uid($seed);
            self::assertStringStartsWith('uid=0(root) gid=0(root) groups=0(root)', $uid, "seed={$seed}");
            // It is meant to sit in a header value (Confluence X-Cmd-Response), so it MUST stay CR/LF/NUL-free.
            self::assertSame(0, preg_match('/[\r\n\x00]/', $uid), "seed={$seed}: uid must be CR/LF/NUL-free");
        }
    }

    public function test_environ_keeps_path_and_user_markers_and_is_nul_separated_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            $environ = CannedData::environ($seed);
            self::assertStringContainsString('PATH=', $environ, "seed={$seed}");
            self::assertStringContainsString('USER=', $environ, "seed={$seed}");
            self::assertStringContainsString("\x00", $environ, "seed={$seed}");
        }
    }

    public function test_ssh_private_key_is_a_valid_but_inert_pem_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            $pem = CannedData::sshPrivateKey($seed);
            self::assertStringStartsWith('-----BEGIN OPENSSH PRIVATE KEY-----', $pem, "seed={$seed}");
            self::assertStringContainsString('-----END OPENSSH PRIVATE KEY-----', $pem, "seed={$seed}");

            preg_match('/-----BEGIN OPENSSH PRIVATE KEY-----\n(.*)\n-----END/s', $pem, $m);
            $blob = base64_decode(str_replace("\n", '', $m[1] ?? ''), true);
            self::assertNotFalse($blob, "seed={$seed}: the key body must be well-formed base64");
            // A real OpenSSH private key blob begins with this magic; ours must NOT, so it is a
            // structurally invalid, non-functional key that authenticates nowhere.
            self::assertStringStartsNotWith("openssh-key-v1\0", (string) $blob, "seed={$seed}");
        }
    }

    public function test_hostname_is_a_single_plausible_line_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            self::assertSame(1, preg_match('/^[a-z0-9][a-z0-9.-]{1,62}\n$/', CannedData::hostname($seed)), "seed={$seed}");
        }
    }

    public function test_winini_and_k8s_are_unchanged_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            self::assertStringContainsString('[extensions]', CannedData::winini($seed), "seed={$seed}");
            self::assertSame(CannedData::WININI, CannedData::winini($seed), "seed={$seed}");
            self::assertSame(CannedData::K8S_SA_UNSIGNED, CannedData::k8sSaUnsigned($seed), "seed={$seed}");
            // The served k8s token's payload still decodes to the default:default serviceaccount claim.
            $payload = explode('.', CannedData::k8sSaUnsigned($seed))[1];
            $decoded = (string) base64_decode(strtr($payload, '-_', '+/'), false);
            self::assertStringContainsString('system:serviceaccount:default:default', $decoded, "seed={$seed}");
        }
    }

    // --- served-byte safety ----------------------------------------------------------------------

    public function test_every_accessor_is_fingerprint_clean_at_every_seed(): void
    {
        // The static gate never sees these rendered bytes; a `.`/`/`-bounded 6-digit run in the shadow
        // hash or SSH body could carry the denylist token invisibly — the reroll guard is what keeps
        // this green, so assert it directly across the sweep.
        $guard = FingerprintGuard::fromPackage();
        foreach (self::SEEDS as $seed) {
            foreach ($this->allSurfaces($seed) as $name => $value) {
                self::assertSame([], $guard->scan($value), "seed={$seed}: {$name} carries a fingerprint token");
            }
        }
    }

    public function test_no_canned_surface_carries_a_brand_tell_at_every_seed(): void
    {
        foreach (self::SEEDS as $seed) {
            foreach ($this->allSurfaces($seed) as $name => $value) {
                self::assertStringNotContainsStringIgnoringCase('fnpot', $value, "{$name} leaks a brand tell at seed={$seed}");
                self::assertStringNotContainsStringIgnoringCase('funnypot', $value, "{$name} leaks a brand tell at seed={$seed}");
            }
        }
    }

    // --- determinism + cross-deploy variance -----------------------------------------------------

    public function test_each_accessor_is_deterministic_within_a_deploy(): void
    {
        foreach (self::SEEDS as $seed) {
            foreach ($this->allSurfaces($seed) as $name => $value) {
                self::assertSame($value, $this->allSurfaces($seed)[$name], "seed={$seed}: {$name} must be a pure function of the seed");
            }
        }
    }

    public function test_varied_surfaces_differ_across_deploy_seeds(): void
    {
        $a = PersonaIdentity::seedFromMaterial('fp-0277-sample-a');
        $b = PersonaIdentity::seedFromMaterial('fp-0277-sample-b');

        // The fleet-correlation surfaces the ticket names must differ across two deploys.
        self::assertNotSame(CannedData::passwd($a), CannedData::passwd($b), 'passwd must vary per deploy');
        self::assertNotSame(CannedData::shadow($a), CannedData::shadow($b), 'shadow must vary per deploy');
        self::assertNotSame(CannedData::group($a), CannedData::group($b), 'group must vary per deploy');
        self::assertNotSame(CannedData::hostname($a), CannedData::hostname($b), 'hostname must vary per deploy');
        self::assertNotSame(CannedData::sshPrivateKey($a), CannedData::sshPrivateKey($b), 'ssh key body must vary per deploy');
        self::assertNotSame(CannedData::environ($a), CannedData::environ($b), 'environ must vary per deploy');

        // The deferred surfaces are identical across deploys (documented non-change).
        self::assertSame(CannedData::winini($a), CannedData::winini($b), 'winini is unchanged');
        self::assertSame(CannedData::k8sSaUnsigned($a), CannedData::k8sSaUnsigned($b), 'k8s SA token unsigned portion is unchanged');
    }

    public function test_render_dispatch_matches_the_per_key_accessors(): void
    {
        $seed = 4242;
        self::assertSame(CannedData::passwd($seed), CannedData::render('passwd', $seed));
        self::assertSame(CannedData::shadow($seed), CannedData::render('shadow', $seed));
        self::assertSame(CannedData::group($seed), CannedData::render('group', $seed));
        self::assertSame(CannedData::hostname($seed), CannedData::render('hostname', $seed));
        self::assertSame(CannedData::sshPrivateKey($seed), CannedData::render('ssh_private_key', $seed));
        self::assertSame(CannedData::environ($seed), CannedData::render('environ', $seed));
        self::assertSame(CannedData::uid($seed), CannedData::render('uid', $seed));
        self::assertSame(CannedData::WININI, CannedData::render('winini', $seed));
        self::assertSame(CannedData::K8S_SA_UNSIGNED, CannedData::render('k8s_sa_unsigned', $seed));
        // Unknown key -> null so the renderer's `|`-alternatives still cascade.
        self::assertNull(CannedData::render('nope', $seed));
    }

    /**
     * @return array<string,string>
     */
    private function allSurfaces(int $seed): array
    {
        return [
            'passwd' => CannedData::passwd($seed),
            'shadow' => CannedData::shadow($seed),
            'group' => CannedData::group($seed),
            'hostname' => CannedData::hostname($seed),
            'ssh_private_key' => CannedData::sshPrivateKey($seed),
            'environ' => CannedData::environ($seed),
            'uid' => CannedData::uid($seed),
            'winini' => CannedData::winini($seed),
            'k8s_sa_unsigned' => CannedData::k8sSaUnsigned($seed),
        ];
    }
}
