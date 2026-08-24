<?php
declare(strict_types=1);
namespace Funnypot\Tests\Support\Chrome;

use Funnypot\Support\Chrome\PathSegments;
use PHPUnit\Framework\TestCase;

/**
 * Covers the 7.3-ported segment matchers (str_starts_with -> strncmp, arrow fn -> named helper):
 * the ported logic must behave byte-identically to the original PHP 8.0 arrow-fn/str_starts_with
 * version this was derived from.
 */
final class PathSegmentsTest extends TestCase
{
    public function test_of_splits_and_drops_empty_segments(): void
    {
        self::assertSame(['admin', 'users'], PathSegments::of('/admin/users/'));
        self::assertSame([], PathSegments::of(''));
        self::assertSame([], PathSegments::of('///'));
    }

    public function test_has_matches_whole_segment_only(): void
    {
        self::assertTrue(PathSegments::has('/admin/users', 'admin'));
        self::assertFalse(PathSegments::has('/user/admin-notes', 'admin'), 'a substring buried in a longer segment must not match');
        self::assertFalse(PathSegments::has('/administer', 'admin'));
    }

    public function test_has_prefixed_matches_segment_prefix(): void
    {
        self::assertTrue(PathSegments::hasPrefixed('/wp-login.php', 'wp-'));
        self::assertTrue(PathSegments::hasPrefixed('/wp-admin/edit.php', 'wp-'));
        self::assertFalse(PathSegments::hasPrefixed('/hr/portal', 'wp-'));
        self::assertFalse(PathSegments::hasPrefixed('', 'wp-'));
    }

    public function test_has_segment_or_dot_suffix(): void
    {
        self::assertTrue(PathSegments::hasSegmentOrDotSuffix('/admin', 'admin'));
        self::assertTrue(PathSegments::hasSegmentOrDotSuffix('/admin.php', 'admin'));
        self::assertTrue(PathSegments::hasSegmentOrDotSuffix('/admin.aspx', 'admin'));
        self::assertFalse(PathSegments::hasSegmentOrDotSuffix('/admin-notes', 'admin'), 'a dash right after the token is not a boundary');
        self::assertFalse(PathSegments::hasSegmentOrDotSuffix('/administer', 'admin'));
    }

    public function test_starts_with_segment_then_more(): void
    {
        self::assertTrue(PathSegments::startsWithSegmentThenMore('/d/abc123', 'd'));
        self::assertFalse(PathSegments::startsWithSegmentThenMore('/d', 'd'), 'the leading segment alone with nothing after it must not match');
        self::assertFalse(PathSegments::startsWithSegmentThenMore('/other/d/abc123', 'd'), 'd must be the FIRST segment, not merely present');
    }
}
