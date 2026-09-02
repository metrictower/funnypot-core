<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Rules;

use Funnypot\Core\Rules\ReDosGuard;
use Funnypot\Core\Rules\RulesUpdateException;
use PHPUnit\Framework\TestCase;

/**
 * The widened, shape-agnostic ReDoS walk: every string value keyed `regex`, at any depth, is screened
 * with its sibling ci/dotall flags, so an un-screened regex can no longer drift into coverage.
 */
final class ReDosGuardTest extends TestCase
{
    public function test_walk_finds_catastrophic_regex_at_depth(): void
    {
        $guard = new ReDosGuard();
        $tree = ['a' => ['b' => ['c' => [['when' => ['regex' => '(a+)+$']]]]]];

        $this->expectException(RulesUpdateException::class);
        $this->expectExceptionMessageMatches('/backtrack budget/');
        $guard->inspectArtifact($tree, 'deep.php');
    }

    public function test_walk_rejects_uncompilable_regex(): void
    {
        $guard = new ReDosGuard();
        try {
            $guard->inspectArtifact(['x' => ['regex' => '(unterminated']], 'bad.php');
            self::fail('expected an uncompilable regex to be rejected');
        } catch (RulesUpdateException $e) {
            self::assertSame(RulesUpdateException::REASON_REDOS, $e->reason());
        }
    }

    public function test_walk_screens_regex_carrying_sibling_flags(): void
    {
        // A regex node carrying sibling ci/dotall flags (exactly the runtime flag-assembly shape) is
        // still screened — the flags are read and threaded into the compile, and a catastrophic
        // pattern under them fails just the same. A clean flagged pattern passes.
        $guard = new ReDosGuard();
        $this->expectException(RulesUpdateException::class);
        $guard->inspectArtifact(['cond' => ['regex' => '(a+)+$', 'ci' => false, 'dotall' => true]], 'flags.php');
    }

    public function test_clean_regex_with_flags_passes(): void
    {
        $guard = new ReDosGuard();
        $guard->inspectArtifact(['cond' => ['regex' => 'foo=([a-z]+)', 'ci' => true, 'dotall' => true]], 'flags.php');
        $this->addToAssertionCount(1);
    }

    public function test_clean_artifacts_pass(): void
    {
        $guard = new ReDosGuard();
        $tree = [
            'buckets' => [
                '@fs' => [['id' => 'x', 'regex' => '^/@fs/(?P<path>.+)$']],
            ],
            'rules' => [
                ['match' => [['regex' => 'q=([a-z0-9]+)', 'ci' => true]]],
            ],
        ];
        $guard->inspectArtifact($tree, 'clean.php');
        $this->addToAssertionCount(1);
    }

    public function test_walk_depth_cap_terminates(): void
    {
        // A pathologically deep tree must not recurse forever; beyond the cap the walk simply stops
        // (a regex buried below the cap is not screened, but termination is the property under test).
        $guard = new ReDosGuard();
        $node = ['regex' => 'safe'];
        for ($i = 0; $i < 200; $i++) {
            $node = ['child' => $node];
        }
        $guard->inspectArtifact($node, 'deep.php', 32);
        $this->addToAssertionCount(1);
    }

    public function test_identical_patterns_are_deduped(): void
    {
        // Many copies of the same clean pattern are screened once; a smoke test that the seen-set path
        // does not change the pass/fail outcome.
        $guard = new ReDosGuard();
        $rules = [];
        for ($i = 0; $i < 500; $i++) {
            $rules[] = ['match' => [['regex' => 'q=([a-z0-9]+)']]];
        }
        $guard->inspectArtifact($rules, 'dupe.php');
        $this->addToAssertionCount(1);
    }
}
