<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Rules;

use Funnypot\Core\Rules\KeyRing;
use PHPUnit\Framework\TestCase;

/**
 * KeyRing normalisation is FAIL-CLOSED: a malformed validity window (present but unparseable) drops
 * the whole key rather than being ignored, so a typo in the trust root can only ever shrink trust.
 * Role filtering (channels vs release) and overlapping-window rotation are exercised too.
 */
final class KeyRingTest extends TestCase
{
    /** A valid base64 32-byte ed25519 public key placeholder (bytes need not be a real key here). */
    private function pub(): string
    {
        return base64_encode(str_repeat('k', 32));
    }

    /** @param array<string,mixed> $extra */
    private function entry(array $extra): array
    {
        return array_merge(['key_id' => 'k', 'public_key' => $this->pub(), 'roles' => ['release']], $extra);
    }

    public function test_malformed_valid_until_fails_closed(): void
    {
        $ring = new KeyRing([$this->entry(['valid_from' => '2000-01-01', 'valid_until' => 'not-a-date'])]);
        self::assertTrue($ring->isEmpty(), 'an unparseable valid_until must drop the key');
        self::assertSame([], $ring->activeKeys(strtotime('2020-01-01')));
    }

    public function test_malformed_valid_from_fails_closed(): void
    {
        $ring = new KeyRing([$this->entry(['valid_from' => '2026-13-45', 'valid_until' => null])]);
        self::assertTrue($ring->isEmpty(), 'an out-of-range valid_from must drop the key');
    }

    public function test_empty_string_window_fails_closed(): void
    {
        $ring = new KeyRing([$this->entry(['valid_from' => '', 'valid_until' => null])]);
        self::assertTrue($ring->isEmpty(), 'an empty-string window is unparseable and must drop the key');
    }

    public function test_null_windows_remain_unbounded(): void
    {
        $ring = new KeyRing([$this->entry(['valid_from' => null, 'valid_until' => null])]);
        // Unbounded on both ends → active at any time.
        self::assertCount(1, $ring->activeKeys(0, 'release'));
        self::assertCount(1, $ring->activeKeys(strtotime('2099-01-01'), 'release'));
    }

    public function test_absent_windows_remain_unbounded(): void
    {
        $ring = new KeyRing([['key_id' => 'k', 'public_key' => $this->pub(), 'roles' => ['release']]]);
        self::assertCount(1, $ring->activeKeys(strtotime('2050-01-01'), 'release'));
    }

    public function test_out_of_window_key_is_not_offered(): void
    {
        $ring = new KeyRing([$this->entry(['valid_from' => '2026-01-01', 'valid_until' => '2026-12-31'])]);
        self::assertSame([], $ring->activeKeys(strtotime('2025-06-01'), 'release'));
        self::assertSame([], $ring->activeKeys(strtotime('2027-06-01'), 'release'));
        self::assertCount(1, $ring->activeKeys(strtotime('2026-06-01'), 'release'));
    }

    public function test_malformed_public_key_is_dropped(): void
    {
        $ring = new KeyRing([['key_id' => 'k', 'public_key' => 'not base64!!', 'roles' => ['release']]]);
        self::assertTrue($ring->isEmpty());
        $short = new KeyRing([['key_id' => 'k', 'public_key' => base64_encode('short'), 'roles' => ['release']]]);
        self::assertTrue($short->isEmpty(), 'a public key that is not 32 bytes must drop the entry');
    }

    public function test_role_filtering_excludes_wrong_role(): void
    {
        $ring = new KeyRing([
            $this->entry(['key_id' => 'r', 'valid_from' => null, 'valid_until' => null, 'roles' => ['release']]),
            $this->entry(['key_id' => 'c', 'valid_from' => null, 'valid_until' => null, 'roles' => ['channels']]),
        ]);
        $release = $ring->activeKeys(null, 'release');
        self::assertCount(1, $release);
        self::assertSame('r', $release[0]['key_id']);

        $channels = $ring->activeKeys(null, 'channels');
        self::assertCount(1, $channels);
        self::assertSame('c', $channels[0]['key_id']);
    }

    public function test_entry_without_roles_matches_no_role(): void
    {
        $ring = new KeyRing([['key_id' => 'k', 'public_key' => $this->pub(), 'valid_from' => null, 'valid_until' => null]]);
        self::assertFalse($ring->isEmpty(), 'the entry is retained (valid key)...');
        self::assertSame([], $ring->activeKeys(null, 'release'), '...but matches no role, fail-closed');
        self::assertSame([], $ring->activeKeys(null, 'channels'));
        // With no role filter it is still returned (legacy/direct callers).
        self::assertCount(1, $ring->activeKeys(null, null));
    }

    public function test_dual_role_key_matches_both(): void
    {
        $ring = new KeyRing([$this->entry(['valid_from' => null, 'valid_until' => null, 'roles' => ['release', 'channels']])]);
        self::assertCount(1, $ring->activeKeys(null, 'release'));
        self::assertCount(1, $ring->activeKeys(null, 'channels'));
    }

    public function test_window_rotation_overlap_still_works(): void
    {
        // The documented rotation: an outgoing key with a valid_until and an incoming key with a
        // future valid_from that overlaps it — both trusted during the overlap window.
        $ring = new KeyRing([
            $this->entry(['key_id' => 'old', 'valid_from' => '2026-01-01', 'valid_until' => '2026-06-30', 'roles' => ['release']]),
            $this->entry(['key_id' => 'new', 'valid_from' => '2026-06-01', 'valid_until' => null, 'roles' => ['release']]),
        ]);
        $mid = strtotime('2026-06-15');
        $ids = array_column($ring->activeKeys($mid, 'release'), 'key_id');
        sort($ids);
        self::assertSame(['new', 'old'], $ids, 'both keys are trusted during the overlap');

        $after = strtotime('2026-09-01');
        self::assertSame(['new'], array_column($ring->activeKeys($after, 'release'), 'key_id'));
    }

    public function test_rfc3339_window_is_parsed(): void
    {
        $ring = new KeyRing([$this->entry(['valid_from' => '2026-01-01T00:00:00+00:00', 'valid_until' => null])]);
        self::assertSame([], $ring->activeKeys(strtotime('2025-12-31T00:00:00Z'), 'release'));
        self::assertCount(1, $ring->activeKeys(strtotime('2026-02-01T00:00:00Z'), 'release'));
    }
}
