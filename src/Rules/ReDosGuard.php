<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

/**
 * Fetch-time ReDoS screen for incoming attack-rule regexes.
 *
 * TemplateAttackEmulator runs `preg_match('~'.$cond['regex'].'~'.$flags, $surface)` on
 * attacker-controlled request bytes (capped at 32 KB). A poisoned rule doesn't need to hang
 * once — a pattern like `(a+)+$` can burn a large backtrack budget on EVERY matching request.
 * The build-time RE2 witness check does not cover this: these conditions run under PCRE.
 *
 * So before a release goes live, every incoming `regex` condition is compiled and run against
 * a handful of adversarial surfaces under a tight PCRE backtrack budget. A pattern that fails
 * to compile, or that trips PREG_BACKTRACK_LIMIT_ERROR on any surface, fails the whole update.
 *
 * The surfaces are SHORT on purpose. Catastrophic (exponential) backtracking explodes on a
 * few dozen characters — `(a+)+$` on 40 chars is ~2^40 steps — while the shipped CRS-derived
 * patterns are large but POLYNOMIAL: broad alternations that stay cheap on short input and are
 * bounded at runtime by the 32 KB surface cap plus PHP's 1,000,000 backtrack limit. Probing at
 * the full 32 KB would reject that legitimate baseline; probing short cleanly separates the two.
 * The honest limit: this catches EXPONENTIAL blow-ups, not merely-expensive polynomial patterns
 * (those the runtime already bounds and fails safe on).
 */
final class ReDosGuard
{
    /** @var int */
    private $backtrackBudget;

    /** @var int */
    private $surfaceBytes;

    public function __construct(int $backtrackBudget = 200000, int $surfaceBytes = 64)
    {
        $this->backtrackBudget = $backtrackBudget;
        $this->surfaceBytes = $surfaceBytes;
    }

    /**
     * @param array<int,array<string,mixed>> $rules compiled attack rules
     * @throws RulesUpdateException on the first pattern that fails to compile or blows the budget
     */
    public function inspectRules(array $rules): void
    {
        foreach ($rules as $rule) {
            $id = (string) ($rule['id'] ?? '?');
            foreach ((array) ($rule['match'] ?? []) as $cond) {
                if (!isset($cond['regex'])) {
                    continue;
                }
                $ci = ($cond['ci'] ?? true) !== false;
                $dotall = ($cond['dotall'] ?? false) === true;
                $this->inspectPattern((string) $cond['regex'], $ci, $dotall, $id);
            }
        }
    }

    /**
     * @throws RulesUpdateException
     */
    public function inspectPattern(string $regex, bool $ci, bool $dotall, string $id): void
    {
        $flags = ($ci ? 'i' : '') . ($dotall ? 's' : '');
        $pattern = '~' . $regex . '~' . $flags;

        if (@preg_match($pattern, '') === false) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_REDOS,
                "Attack rule '{$id}' has a regex that does not compile."
            );
        }

        $previous = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', (string) $this->backtrackBudget);
        try {
            foreach ($this->adversarialSurfaces() as $surface) {
                @preg_match($pattern, $surface);
                if (preg_last_error() === PREG_BACKTRACK_LIMIT_ERROR) {
                    throw new RulesUpdateException(
                        RulesUpdateException::REASON_REDOS,
                        "Attack rule '{$id}' regex exceeds the {$this->backtrackBudget}-step backtrack budget "
                        . '(catastrophic backtracking risk).'
                    );
                }
            }
        } finally {
            ini_set('pcre.backtrack_limit', $previous === false ? '1000000' : $previous);
        }
    }

    /**
     * Short inputs chosen to provoke the classic nested-quantifier blow-ups. A trailing
     * non-matching byte forces the engine to exhaust every backtrack branch (the worst case).
     *
     * @return string[]
     */
    private function adversarialSurfaces(): array
    {
        $n = max(16, $this->surfaceBytes);

        return [
            str_repeat('a', $n) . '!',
            str_repeat('a1', intdiv($n, 2)) . '!',
            str_repeat('/', $n) . 'x',
            str_repeat('0', $n) . '!',
            str_repeat('aA0-_ (){}[]', max(2, intdiv($n, 12))) . '!',
        ];
    }
}
