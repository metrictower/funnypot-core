<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

use Funnypot\Compiler\ConstraintMerge;
use Funnypot\Compiler\DynamicLiteralScreen;

/**
 * Inverts a `dsl` matcher block, but ONLY for the whitelisted subset (§3):
 *
 *   status_code == N            len(body) ==|>|<|>=|<= N
 *   contains[/tolower/to_lower](body|all_headers|header, 'x')
 *   !contains(...) -> forbidden
 *   contains_all(region, 'a', 'b', ...)   contains_any(region, ...)
 *   startswith(region, 'x')   endswith(region, 'x')
 *   && (conjunction)   || (disjunction)
 *
 * Anything else — `regex(`, `_py(`, `md5(`, `compare_versions(`, `duration`, arithmetic
 * on variables, a bare extracted identifier, an unsupported header field — throws
 * {@see DslUnsupported} and folds the matcher OUT. `startswith`/`endswith` positioning
 * is approximated as containment here; the synthesizer places the literal at the
 * boundary and the Phase 6 golden test certifies it.
 */
final class DslInverter
{
    /** @var array<int,array{t:string,v:string}> */
    private array $tok = [];
    private int $p = 0;

    /**
     * @param array<string,mixed> $m
     */
    public function invert(array $m): MatcherResult
    {
        if (!empty($m['negative'])) {
            return MatcherResult::out('dsl-negative-unsupported');
        }

        $exprs = $m['dsl'] ?? [];
        if (!is_array($exprs)) {
            $exprs = [$exprs];
        }
        $exprs = array_values(array_map(static fn ($e): string => (string) $e, $exprs));
        if ($exprs === []) {
            return MatcherResult::out('dsl-empty');
        }

        $blockAnd = strtolower((string) ($m['condition'] ?? '')) === 'and';

        $results = [];
        $lastReason = 'dsl-unsupported';
        foreach ($exprs as $expr) {
            try {
                $results[] = $this->parseExpression($expr);
            } catch (DslUnsupported $e) {
                if ($blockAnd) {
                    return MatcherResult::out($e->getMessage());
                }
                $lastReason = $e->getMessage();
            }
        }

        if ($results === []) {
            return MatcherResult::out($lastReason);
        }

        if ($blockAnd) {
            $acc = $results[0];
            for ($k = 1; $k < count($results); $k++) {
                $acc = ConstraintMerge::and($acc, $results[$k]);
                if (!$acc->ok) {
                    return $acc;
                }
            }

            return $acc;
        }

        // Block OR: one satisfied expression is enough.
        return $results[0];
    }

    private function parseExpression(string $expr): MatcherResult
    {
        $this->tokenize($expr);
        $this->p = 0;
        $r = $this->parseOr();
        if (!$this->eof()) {
            throw new DslUnsupported('dsl-trailing-tokens');
        }
        if (!$r->ok) {
            throw new DslUnsupported($r->reason);
        }

        return $r;
    }

    // ---- grammar ----

    private function parseOr(): MatcherResult
    {
        // Disjunction: any one branch satisfies, so an unsupported branch must not sink
        // a supported sibling ("satisfy the cheapest"). Each branch is parsed in
        // isolation; a failing one is recovered past to the next top-level `||`.
        $branches = [];
        $branches[] = $this->parseBranch();
        while ($this->peekType() === 'op' && $this->peekVal() === '||') {
            $this->next();
            $branches[] = $this->parseBranch();
        }

        foreach ($branches as $b) {
            if ($b->ok) {
                return $b;
            }
        }

        // Surface a representative reason from the last failed branch.
        return MatcherResult::out($branches[count($branches) - 1]->reason ?: 'dsl-or-all-out');
    }

    private function parseBranch(): MatcherResult
    {
        try {
            return $this->parseAnd();
        } catch (DslUnsupported $e) {
            $this->recoverToOr();

            return MatcherResult::out($e->getMessage());
        }
    }

    /**
     * After a failed branch, advance to the next top-level `||` (or the end / the close
     * of an enclosing group) so sibling branches can still be tried.
     */
    private function recoverToOr(): void
    {
        $depth = 0;
        while (!$this->eof()) {
            $t = $this->tok[$this->p];
            if ($t['t'] === 'punc' && $t['v'] === '(') {
                $depth++;
            } elseif ($t['t'] === 'punc' && $t['v'] === ')') {
                if ($depth === 0) {
                    return; // belongs to an enclosing group
                }
                $depth--;
            } elseif ($t['t'] === 'op' && $t['v'] === '||' && $depth === 0) {
                return;
            }
            $this->p++;
        }
    }

    private function parseAnd(): MatcherResult
    {
        $acc = $this->parseUnary();
        while ($this->peekType() === 'op' && $this->peekVal() === '&&') {
            $this->next();
            $acc = ConstraintMerge::and($acc, $this->parseUnary());
            if (!$acc->ok) {
                throw new DslUnsupported($acc->reason);
            }
        }

        return $acc;
    }

    private function parseUnary(): MatcherResult
    {
        $neg = false;
        while ($this->peekType() === 'op' && $this->peekVal() === '!') {
            $neg = !$neg;
            $this->next();
        }

        return $this->parsePrimary($neg);
    }

    private function parsePrimary(bool $neg): MatcherResult
    {
        if ($this->peekType() === 'punc' && $this->peekVal() === '(') {
            if ($neg) {
                // Negating a parenthesized compound needs De Morgan — out of scope.
                throw new DslUnsupported('dsl-negated-group');
            }
            $this->next();
            $r = $this->parseOr();
            $this->expectPunc(')');

            return $r;
        }

        $value = $this->parseValue();

        // Comparison? (status_code / len(...) against a number)
        if ($this->peekType() === 'op' && in_array($this->peekVal(), ['==', '!=', '>', '<', '>=', '<='], true)) {
            $op = $this->next()['v'];
            $rhs = $this->parseValue();

            return $this->comparison($value, $op, $rhs, $neg);
        }

        return $this->booleanFunc($value, $neg);
    }

    /**
     * @return array{kind:string,name?:string,args?:array,v?:string,region?:string}
     */
    private function parseValue(): array
    {
        $t = $this->peek();
        if ($t === null) {
            throw new DslUnsupported('dsl-unexpected-eof');
        }

        if ($t['t'] === 'num') {
            $this->next();

            return ['kind' => 'num', 'v' => $t['v']];
        }
        if ($t['t'] === 'str') {
            $this->next();

            return ['kind' => 'str', 'v' => $t['v']];
        }
        if ($t['t'] === 'ident') {
            $this->next();
            if ($this->peekType() === 'punc' && $this->peekVal() === '(') {
                $this->next();
                $args = $this->parseArgs();

                return ['kind' => 'func', 'name' => strtolower($t['v']), 'args' => $args];
            }

            return ['kind' => 'ident', 'name' => strtolower($t['v'])];
        }

        throw new DslUnsupported('dsl-unexpected-token');
    }

    /**
     * @return array<int,array{kind:string,name?:string,args?:array,v?:string}>
     */
    private function parseArgs(): array
    {
        $args = [];
        if ($this->peekType() === 'punc' && $this->peekVal() === ')') {
            $this->next();

            return $args;
        }
        while (true) {
            $args[] = $this->parseValue();
            if ($this->peekType() === 'punc' && $this->peekVal() === ',') {
                $this->next();
                continue;
            }
            break;
        }
        $this->expectPunc(')');

        return $args;
    }

    /**
     * status_code / len(region) compared against an integer.
     *
     * @param array{kind:string,name?:string,args?:array,v?:string} $lhs
     * @param array{kind:string,name?:string,args?:array,v?:string} $rhs
     */
    private function comparison(array $lhs, string $op, array $rhs, bool $neg): MatcherResult
    {
        if (($rhs['kind'] ?? '') !== 'num') {
            throw new DslUnsupported('dsl-compare-non-numeric');
        }
        $n = (int) $rhs['v'];
        $r = MatcherResult::in();

        if (($lhs['kind'] ?? '') === 'ident' && ($lhs['name'] ?? '') === 'status_code') {
            $eq = ($op === '==' && !$neg) || ($op === '!=' && $neg);
            $ne = ($op === '!=' && !$neg) || ($op === '==' && $neg);
            if ($eq) {
                $r->statusAllowed = [$n];

                return $r;
            }
            if ($ne) {
                $r->statusForbidden = [$n];

                return $r;
            }
            throw new DslUnsupported('dsl-status-op-unsupported');
        }

        if (($lhs['kind'] ?? '') === 'func' && ($lhs['name'] ?? '') === 'len') {
            if ($neg) {
                throw new DslUnsupported('dsl-negated-len');
            }
            $region = $this->regionOfArg($lhs['args'][0] ?? null);
            if ($region !== PartRouter::BODY) {
                throw new DslUnsupported('dsl-len-region');
            }
            $r->size = $this->sizeOp($op, $n);
            $r->wholeBodyExclusive = true;

            return $r;
        }

        throw new DslUnsupported('dsl-compare-unsupported');
    }

    /**
     * @return array{op:string,n:int}
     */
    private function sizeOp(string $op, int $n): array
    {
        switch ($op) {
            case '==':
                return ['op' => 'eq', 'n' => $n];
            case '>':
                return ['op' => 'min', 'n' => $n + 1];
            case '>=':
                return ['op' => 'min', 'n' => $n];
            case '<':
                return ['op' => 'max', 'n' => max(0, $n - 1)];
            case '<=':
                return ['op' => 'max', 'n' => $n];
            default:
                throw new DslUnsupported('dsl-len-op');
        }
    }

    /**
     * contains / contains_all / contains_any / startswith / endswith.
     *
     * @param array{kind:string,name?:string,args?:array,v?:string} $value
     */
    private function booleanFunc(array $value, bool $neg): MatcherResult
    {
        if (($value['kind'] ?? '') !== 'func') {
            throw new DslUnsupported('dsl-non-boolean-term');
        }
        $name = $value['name'] ?? '';
        $args = $value['args'] ?? [];

        if (!in_array($name, ['contains', 'contains_all', 'contains_any', 'startswith', 'endswith'], true)) {
            throw new DslUnsupported('dsl-func:' . $name);
        }
        if (count($args) < 2) {
            throw new DslUnsupported('dsl-func-arity');
        }

        $region = $this->regionOfArg($args[0]);
        if ($region === PartRouter::UNSUPPORTED) {
            throw new DslUnsupported('dsl-region-unsupported');
        }

        $literals = [];
        for ($k = 1; $k < count($args); $k++) {
            if (($args[$k]['kind'] ?? '') !== 'str') {
                throw new DslUnsupported('dsl-non-literal-arg');
            }
            $literals[] = (string) $args[$k]['v'];
        }

        $anyMode = $name === 'contains_any';
        // required = present; forbidden when negated (De Morgan keeps it satisfiable).
        $forbid = $neg;
        $typed = $this->isTyped($region) ? $region : null;

        $r = MatcherResult::in();
        $resolvable = array_values(array_filter(
            $literals,
            static fn (string $l): bool => DynamicLiteralScreen::isResolvable($l)
        ));

        if ($forbid) {
            // A typed-header negative cannot be honoured without emitting that exact header
            // absent the literal; fold rather than under-constrain the whole block.
            if ($typed !== null) {
                throw new DslUnsupported('dsl-typed-negative');
            }
            // Forbidding an unpredictable literal is free (we never emit it).
            foreach ($resolvable as $lit) {
                $this->addForbidden($r, $region, $lit);
            }

            return $r;
        }

        if ($resolvable === []) {
            throw new DslUnsupported('dsl-dynamic-literal');
        }

        if ($anyMode) {
            // One present satisfies; require the first resolvable literal.
            $this->place($r, $typed, $region, $resolvable[0]);

            return $r;
        }

        // contains / contains_all / startswith / endswith: all listed literals required.
        if (count($resolvable) !== count($literals)) {
            throw new DslUnsupported('dsl-dynamic-literal');
        }
        foreach ($resolvable as $lit) {
            $this->place($r, $typed, $region, $lit);
        }

        return $r;
    }

    /**
     * @param array{kind:string,name?:string,args?:array,v?:string}|null $arg
     */
    private function regionOfArg($arg): string
    {
        if (!is_array($arg)) {
            throw new DslUnsupported('dsl-region-missing');
        }

        // Unwrap tolower(...) / to_lower(...) wrappers.
        while (($arg['kind'] ?? '') === 'func' && in_array($arg['name'] ?? '', ['tolower', 'to_lower'], true)) {
            $inner = $arg['args'][0] ?? null;
            if (!is_array($inner)) {
                throw new DslUnsupported('dsl-region-wrap');
            }
            $arg = $inner;
        }

        if (($arg['kind'] ?? '') !== 'ident') {
            throw new DslUnsupported('dsl-region-non-ident');
        }
        $name = $arg['name'] ?? '';
        if ($name === 'body') {
            return PartRouter::BODY;
        }
        if ($name === 'all_headers' || $name === 'header') {
            return PartRouter::HEADER;
        }

        // A typed-header region (content_type / server / …) is returned as its Go-canonical
        // header name; numbered/second-request idents (content_type_1) are unsupported.
        $typed = PartRouter::typedHeader($name);
        if ($typed !== null) {
            return $typed;
        }

        return PartRouter::UNSUPPORTED;
    }

    /** A region string that is neither body nor the header block nor unsupported is a typed header. */
    private function isTyped(string $region): bool
    {
        return $region !== PartRouter::BODY
            && $region !== PartRouter::HEADER
            && $region !== PartRouter::UNSUPPORTED;
    }

    /**
     * Route a required literal: a typed header pins it to that header's value (mirrored into
     * the block for the block-level machinery); otherwise it is a plain body/header substring.
     */
    private function place(MatcherResult $r, ?string $typed, string $region, string $lit): void
    {
        if ($typed !== null) {
            $r->typedHeader[$typed][] = $lit;
            $r->headerWords[] = $lit;

            return;
        }
        $this->addRequired($r, $region, $lit);
    }

    private function addRequired(MatcherResult $r, string $region, string $lit): void
    {
        if ($region === PartRouter::HEADER) {
            $r->headerWords[] = $lit;
        } else {
            $r->bodyWords[] = $lit;
        }
    }

    private function addForbidden(MatcherResult $r, string $region, string $lit): void
    {
        if ($region === PartRouter::HEADER) {
            $r->headerForbidden[] = $lit;
        } else {
            $r->forbidden[] = $lit;
        }
    }

    // ---- tokenizer ----

    private function tokenize(string $s): void
    {
        $this->tok = [];
        $len = strlen($s);
        $i = 0;
        while ($i < $len) {
            $c = $s[$i];

            if (ctype_space($c)) {
                $i++;
                continue;
            }

            // string literal (single or double quoted)
            if ($c === "'" || $c === '"') {
                [$val, $i] = $this->readString($s, $i, $c);
                $this->tok[] = ['t' => 'str', 'v' => $val];
                continue;
            }

            // multi-char operators
            $two = substr($s, $i, 2);
            if (in_array($two, ['==', '!=', '>=', '<=', '&&', '||'], true)) {
                $this->tok[] = ['t' => 'op', 'v' => $two];
                $i += 2;
                continue;
            }
            if ($c === '!' || $c === '>' || $c === '<') {
                $this->tok[] = ['t' => 'op', 'v' => $c];
                $i++;
                continue;
            }
            if ($c === '(' || $c === ')' || $c === ',') {
                $this->tok[] = ['t' => 'punc', 'v' => $c];
                $i++;
                continue;
            }

            if (ctype_digit($c)) {
                $j = $i;
                while ($j < $len && ctype_digit($s[$j])) {
                    $j++;
                }
                $this->tok[] = ['t' => 'num', 'v' => substr($s, $i, $j - $i)];
                $i = $j;
                continue;
            }

            // identifier: letters, digits, underscore
            if (ctype_alpha($c) || $c === '_') {
                $j = $i;
                while ($j < $len && (ctype_alnum($s[$j]) || $s[$j] === '_')) {
                    $j++;
                }
                $this->tok[] = ['t' => 'ident', 'v' => substr($s, $i, $j - $i)];
                $i = $j;
                continue;
            }

            // Any other byte (arithmetic +, -, *, /, %, =, concatenation dots, etc.)
            // is outside the whitelist.
            throw new DslUnsupported('dsl-token:' . $c);
        }
    }

    /**
     * @return array{0:string,1:int}
     */
    private function readString(string $s, int $i, string $quote): array
    {
        $len = strlen($s);
        $i++; // opening quote
        $out = '';
        while ($i < $len) {
            $c = $s[$i];
            if ($c === '\\' && $i + 1 < $len) {
                $out .= $s[$i + 1];
                $i += 2;
                continue;
            }
            if ($c === $quote) {
                // doubled quote escape ('' or "")
                if ($i + 1 < $len && $s[$i + 1] === $quote) {
                    $out .= $quote;
                    $i += 2;
                    continue;
                }

                return [$out, $i + 1];
            }
            $out .= $c;
            $i++;
        }

        throw new DslUnsupported('dsl-unterminated-string');
    }

    // ---- token cursor ----

    /** @return array{t:string,v:string}|null */
    private function peek(): ?array
    {
        return $this->tok[$this->p] ?? null;
    }

    private function peekType(): string
    {
        return $this->tok[$this->p]['t'] ?? '';
    }

    private function peekVal(): string
    {
        return $this->tok[$this->p]['v'] ?? '';
    }

    /** @return array{t:string,v:string} */
    private function next(): array
    {
        $t = $this->tok[$this->p] ?? null;
        if ($t === null) {
            throw new DslUnsupported('dsl-unexpected-eof');
        }
        $this->p++;

        return $t;
    }

    private function eof(): bool
    {
        return $this->p >= count($this->tok);
    }

    private function expectPunc(string $v): void
    {
        if ($this->peekType() !== 'punc' || $this->peekVal() !== $v) {
            throw new DslUnsupported('dsl-expected:' . $v);
        }
        $this->next();
    }
}
