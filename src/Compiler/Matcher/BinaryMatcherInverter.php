<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

/**
 * Inverts a `binary` matcher block (match.go `MatchBinary`).
 *
 * Binary patterns are always hex-encoded in the template and hex-decoded to raw bytes
 * at compile time (compile.go). The decoded bytes must appear in the matched part —
 * identical containment semantics to `word`, so the same and/or and negative folding
 * applies. Only 8 binary matchers exist across the http corpus.
 */
final class BinaryMatcherInverter
{
    /**
     * @param array<string,mixed> $m
     */
    public function invert(array $m): MatcherResult
    {
        $region = PartRouter::region((string) ($m['part'] ?? ''));
        if ($region === PartRouter::UNSUPPORTED) {
            return MatcherResult::out('binary-part-unsupported:' . strtolower((string) ($m['part'] ?? '')));
        }

        $values = $m['binary'] ?? [];
        if (!is_array($values)) {
            $values = [$values];
        }

        $decoded = [];
        foreach ($values as $v) {
            $bytes = @hex2bin(preg_replace('/\s+/', '', (string) $v) ?? '');
            if ($bytes === false || $bytes === '') {
                return MatcherResult::out('binary-undecodable');
            }
            $decoded[] = $bytes;
        }
        if ($decoded === []) {
            return MatcherResult::out('binary-empty');
        }

        $negative = !empty($m['negative']);
        $condition = strtolower((string) ($m['condition'] ?? ''));
        $allRequired = $condition === 'and';

        $r = MatcherResult::in();
        if ($negative) {
            foreach ($decoded as $b) {
                $this->add($r, $region, $b, true);
            }

            return $r;
        }

        if ($allRequired) {
            foreach ($decoded as $b) {
                $this->add($r, $region, $b, false);
            }

            return $r;
        }

        // OR: one is enough.
        $this->add($r, $region, $decoded[0], false);

        return $r;
    }

    private function add(MatcherResult $r, string $region, string $bytes, bool $forbidden): void
    {
        if ($region === PartRouter::HEADER) {
            if ($forbidden) {
                $r->headerForbidden[] = $bytes;
            } else {
                $r->headerWords[] = $bytes;
            }
        } else {
            if ($forbidden) {
                $r->forbidden[] = $bytes;
            } else {
                $r->bodyWords[] = $bytes;
            }
        }
    }
}
