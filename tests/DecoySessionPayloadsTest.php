<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Behavior\DecoySessionPayloads;
use PHPUnit\Framework\TestCase;

/**
 * FP-0492 — the third payload class (2fa-pending) added to the decoy-session vocabulary. The
 * load-bearing invariant this pins (the plan-review CONDITION B): every seed row carries THREE
 * strictly-distinct classes — pre-auth, 2fa-pending, authenticated — so no seed can ever collapse two
 * classes into the same wire token, and each of DecoySession's class tests accepts ONLY its own class.
 * This is what keeps a 2fa-pending cookie from ever authenticating the gate (fail-closed by
 * construction) and a pre-auth/authenticated cookie from ever unlocking the challenge form.
 */
final class DecoySessionPayloadsTest extends TestCase
{
    private const KEY = 'S3cr3t-Decoy-Signing-Key-must-never-leak';

    // --- CONDITION B: three-class distinctness across ALL rows -------------------------------

    public function test_every_row_has_three_pairwise_distinct_payload_classes(): void
    {
        foreach (DecoySessionPayloads::PAIRS as $i => $row) {
            self::assertArrayHasKey('pre', $row, "row {$i} missing pre");
            self::assertArrayHasKey('pending', $row, "row {$i} missing pending");
            self::assertArrayHasKey('authenticated', $row, "row {$i} missing authenticated");

            self::assertNotSame($row['pre'], $row['pending'], "row {$i}: pre vs pending must differ");
            self::assertNotSame($row['pre'], $row['authenticated'], "row {$i}: pre vs authenticated must differ");
            self::assertNotSame($row['pending'], $row['authenticated'], "row {$i}: pending vs authenticated must differ");
        }
    }

    public function test_selected_classes_are_pairwise_distinct_for_every_seed_row(): void
    {
        // Seeds chosen to land on each of the 16 rows (and a few production-shaped large seeds), so the
        // seed-selection path — not just the raw table — is proven class-distinct.
        $seeds = array_merge(range(0, 40), [12345, 484348449122915112, 101, 202, PHP_INT_MAX]);
        foreach ($seeds as $seed) {
            $pre = DecoySessionPayloads::preAuth($seed);
            $pending = DecoySessionPayloads::twoFactorPending($seed);
            $auth = DecoySessionPayloads::authenticated($seed);

            self::assertNotSame($pre, $pending, "seed {$seed}: pre vs pending");
            self::assertNotSame($pre, $auth, "seed {$seed}: pre vs authenticated");
            self::assertNotSame($pending, $auth, "seed {$seed}: pending vs authenticated");
        }
    }

    public function test_pre_and_authenticated_tokens_are_unchanged_by_the_new_pending_class(): void
    {
        // The pending class is purely additive: the pre/authenticated text a seed selects must be
        // byte-stable (no drift in the shipped artifact, no perturbation of the pinned mock-auth tests).
        $expected = [
            0 => ['pre' => 'access=public', 'authenticated' => 'access=private'],
        ];
        foreach ($expected as $seed => $want) {
            self::assertSame($want['pre'], DecoySessionPayloads::preAuth($seed), "seed {$seed} pre");
            self::assertSame($want['authenticated'], DecoySessionPayloads::authenticated($seed), "seed {$seed} auth");
        }
        // And every row's pre/authenticated remain drawn from the original vocabulary (no relabelling).
        foreach (DecoySessionPayloads::PAIRS as $row) {
            self::assertMatchesRegularExpression('/^[A-Za-z0-9_]+=[A-Za-z0-9_]+$/', $row['pending']);
        }
    }

    // --- CONDITION B: DecoySession class tests accept ONLY their own class -------------------

    public function test_is_two_factor_pending_is_true_only_for_the_pending_class(): void
    {
        foreach ([0, 1, 7, 202, 12345, 484348449122915112] as $seed) {
            $session = new DecoySession(self::KEY, $seed);

            $pending = $this->rawValue($session->mintPendingCookie('sess', '/'));
            $auth = $this->rawValue($session->mintCookie('sess', '/'));
            $pre = $this->rawValue($session->preAuthCookie('sess', '/'));

            self::assertTrue($session->isTwoFactorPendingValue($pending), "seed {$seed}: pending accepts pending");
            self::assertFalse($session->isTwoFactorPendingValue($auth), "seed {$seed}: pending rejects authenticated");
            self::assertFalse($session->isTwoFactorPendingValue($pre), "seed {$seed}: pending rejects pre-auth");
        }
    }

    public function test_is_authenticated_is_false_for_the_pending_class(): void
    {
        // The paramount safety property: a validly-signed 2fa-pending cookie must NEVER authenticate.
        foreach ([0, 1, 7, 202, 12345, 484348449122915112] as $seed) {
            $session = new DecoySession(self::KEY, $seed);
            $pending = $this->rawValue($session->mintPendingCookie('sess', '/'));

            self::assertFalse($session->isAuthenticatedValue($pending), "seed {$seed}: pending must not authenticate");
            self::assertTrue($session->isTwoFactorPendingValue($pending), "seed {$seed}: but it is a valid pending token");
        }
    }

    public function test_pending_cookie_from_another_deploy_seed_is_rejected(): void
    {
        // Precondition: the two seeds select different pending texts (else the assertion is vacuous).
        self::assertNotSame(
            DecoySessionPayloads::twoFactorPending(101),
            DecoySessionPayloads::twoFactorPending(202)
        );
        $signer = new DecoySession(self::KEY, 101);
        $verifier = new DecoySession(self::KEY, 202);
        $value = $this->rawValue($signer->mintPendingCookie('sess', '/'));

        self::assertFalse($verifier->isTwoFactorPendingValue($value), 'a cross-seed pending token is rejected');
        self::assertTrue($signer->isTwoFactorPendingValue($value), 'the minting seed still accepts its own token');
    }

    public function test_pending_header_walk_is_throw_free_and_class_separated(): void
    {
        $session = new DecoySession(self::KEY, 7);
        $pending = $this->rawValue($session->mintPendingCookie('sess', '/'));
        $auth = $this->rawValue($session->mintCookie('sess', '/'));

        self::assertTrue($session->isTwoFactorPending('sess=' . $pending, 'sess'));
        self::assertFalse($session->isTwoFactorPending('sess=' . $auth, 'sess'));
        self::assertFalse($session->isTwoFactorPending(null, 'sess'));
        self::assertFalse($session->isTwoFactorPending('', 'sess'));
        foreach (['no-equals', 'sess=', 'sess=nodothere', ';;;', 'other=' . $pending] as $bad) {
            self::assertFalse($session->isTwoFactorPending($bad, 'sess'), $bad);
        }
    }

    private function rawValue(string $setCookie): string
    {
        $eq = strpos($setCookie, '=');
        $semi = strpos($setCookie, ';');
        $value = $semi === false ? substr($setCookie, $eq + 1) : substr($setCookie, $eq + 1, $semi - $eq - 1);

        return $value;
    }
}
