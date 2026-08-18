<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

use Funnypot\Compiler\Matcher\BinaryMatcherInverter;
use Funnypot\Compiler\Matcher\DslInverter;
use Funnypot\Compiler\Matcher\MatcherResult;
use Funnypot\Compiler\Matcher\RegexWitnessGenerator;
use Funnypot\Compiler\Matcher\SizeMatcherInverter;
use Funnypot\Compiler\Matcher\StatusMatcherInverter;
use Funnypot\Compiler\Matcher\WordMatcherInverter;

/**
 * Gate B — per-matcher invertibility folded through `matchers-condition`.
 *
 *   and     -> IN only if EVERY matcher block inverts (constraints unioned)
 *   or/none -> IN if at least ONE block inverts (satisfy the cheapest, ignore the rest)
 *
 * Screens A2 (dynamic literals) and A1/A4 (anchored-regex / exact-size ⇒ whole-body-
 * exclusive) live inside the individual matcher inverters. This class applies B6 —
 * intra-template satisfiability — after folding: a usable status must survive, and no
 * required substring may also be forbidden. A contradiction folds the template OUT.
 */
final class Classifier
{
    private WordMatcherInverter $word;
    private StatusMatcherInverter $status;
    private SizeMatcherInverter $size;
    private BinaryMatcherInverter $binary;
    private RegexWitnessGenerator $regex;
    private DslInverter $dsl;

    /** Preferred status when a template pins none but must avoid some. */
    private const STATUS_FALLBACKS = [200, 404, 403, 500, 301, 302, 401, 400];

    public function __construct()
    {
        $this->word = new WordMatcherInverter();
        $this->status = new StatusMatcherInverter();
        $this->size = new SizeMatcherInverter();
        $this->binary = new BinaryMatcherInverter();
        $this->regex = new RegexWitnessGenerator();
        $this->dsl = new DslInverter();
    }

    public function classify(LoadedTemplate $t): ClassifiedTemplate
    {
        $folded = $this->fold($t);
        if (!$folded->ok) {
            return ClassifiedTemplate::out($folded->reason);
        }

        return $this->finalize($t, $folded);
    }

    private function fold(LoadedTemplate $t): MatcherResult
    {
        $condition = $t->matchersCondition;

        if ($condition === 'and') {
            $acc = null;
            foreach ($t->matchers as $m) {
                $res = $this->invertOne($m);
                if (!$res->ok) {
                    return $res; // one OUT under AND folds the whole template
                }
                $acc = $acc === null ? $res : ConstraintMerge::and($acc, $res);
                if (!$acc->ok) {
                    return $acc; // B6 contradiction surfaced during merge
                }
            }

            return $acc ?? MatcherResult::out('gateB:no-matchers');
        }

        // OR / default: gather invertible blocks, keep the cheapest useful one.
        $candidates = [];
        $lastReason = 'gateB:all-matchers-out';
        foreach ($t->matchers as $m) {
            $res = $this->invertOne($m);
            if ($res->ok) {
                $candidates[] = $res;
            } else {
                $lastReason = $res->reason;
            }
        }
        if ($candidates === []) {
            return MatcherResult::out($lastReason);
        }

        return $this->pickRepresentative($candidates);
    }

    /**
     * @param MatcherResult[] $candidates
     */
    private function pickRepresentative(array $candidates): MatcherResult
    {
        // Prefer a block that actually constrains the response (a positive body/header
        // word, a witness, or a pinned status) so the persona is discriminating.
        foreach ($candidates as $c) {
            if ($c->bodyWords || $c->headerWords || $c->regexWitness || $c->statusAllowed !== null || $c->size) {
                return $c;
            }
        }

        return $candidates[0];
    }

    /**
     * @param mixed $m
     */
    private function invertOne($m): MatcherResult
    {
        if (!is_array($m)) {
            return MatcherResult::out('matcher-malformed');
        }
        $type = strtolower((string) ($m['type'] ?? 'word'));

        switch ($type) {
            case 'word':
                return $this->word->invert($m);
            case 'status':
                return $this->status->invert($m);
            case 'size':
                return $this->size->invert($m);
            case 'binary':
                return $this->binary->invert($m);
            case 'regex':
                return $this->regex->invert($m);
            case 'dsl':
                return $this->dsl->invert($m);
            case 'xpath':
                return MatcherResult::out('matcher-xpath');
            default:
                return MatcherResult::out('matcher-type:' . $type);
        }
    }

    private function finalize(LoadedTemplate $t, MatcherResult $r): ClassifiedTemplate
    {
        $status = $this->chooseStatus($r);
        if ($status === false) {
            return ClassifiedTemplate::out('b6:status-contradiction');
        }

        $reason = $this->requiredForbiddenClash($r);
        if ($reason !== null) {
            return ClassifiedTemplate::out($reason);
        }

        $plan = new SatisfyPlan(
            $t->id,
            $t->severity,
            $t->tags,
            $t->name,
            ProductIdentity::of($t->product, $t->tags),
            $status,
            array_values(array_unique($r->bodyWords)),
            array_values(array_unique($r->headerWords)),
            array_values(array_unique($r->forbidden)),
            array_values(array_unique($r->headerForbidden)),
            array_values(array_unique($r->regexWitness)),
            $r->size,
            $r->wholeBodyExclusive,
            $this->dedupeTypedHeaders($r->typedHeader)
        );

        return ClassifiedTemplate::in($plan);
    }

    /**
     * Collapse the allowed/forbidden status constraints to one status line, or false on
     * an empty allowed set (B6). Returns null when unconstrained and no default is forced.
     *
     * @return int|null|false
     */
    private function chooseStatus(MatcherResult $r)
    {
        $forbidden = array_flip($r->statusForbidden);

        if ($r->statusAllowed !== null) {
            $candidates = array_values(array_filter(
                $r->statusAllowed,
                static fn (int $s): bool => !isset($forbidden[$s])
            ));
            if ($candidates === []) {
                return false;
            }

            return in_array(200, $candidates, true) ? 200 : min($candidates);
        }

        if ($r->statusForbidden === []) {
            return null; // unpinned — synthesizer defaults to 200
        }

        foreach (self::STATUS_FALLBACKS as $s) {
            if (!isset($forbidden[$s])) {
                return $s;
            }
        }

        return 599; // everything common is forbidden; emit an unusual valid code
    }

    /**
     * B6: a required substring must never also be forbidden. Because matching is
     * substring-based, a forbidden string that is contained in a required string is
     * equally unsatisfiable.
     */
    private function requiredForbiddenClash(MatcherResult $r): ?string
    {
        $bodyRequired = array_merge($r->bodyWords, $r->regexWitness);
        if ($this->clash($bodyRequired, $r->forbidden)) {
            return 'b6:body-contradiction';
        }
        if ($this->clash($r->headerWords, $r->headerForbidden)) {
            return 'b6:header-contradiction';
        }

        return null;
    }

    /**
     * @param array<string,string[]> $typed
     * @return array<string,string[]>
     */
    private function dedupeTypedHeaders(array $typed): array
    {
        $out = [];
        foreach ($typed as $name => $subs) {
            $out[$name] = array_values(array_unique($subs));
        }

        return $out;
    }

    /**
     * @param string[] $required
     * @param string[] $forbidden
     */
    private function clash(array $required, array $forbidden): bool
    {
        foreach ($forbidden as $f) {
            if ($f === '') {
                continue;
            }
            foreach ($required as $w) {
                if ($w !== '' && strpos($w, $f) !== false) {
                    return true;
                }
            }
        }

        return false;
    }
}
