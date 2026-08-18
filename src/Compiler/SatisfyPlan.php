<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * A single template's finalized, internally-satisfiable constraint set — the unit the
 * merge colors into bundles. Region-separated (body vs header block) to mirror nuclei's
 * distinct match corpora.
 */
final class SatisfyPlan
{
    /**
     * @param string[]                     $tags
     * @param string[]                     $bodyWords
     * @param string[]                     $headerWords
     * @param string[]                     $forbidden
     * @param string[]                     $headerForbidden
     * @param string[]                     $regexWitness
     * @param array{op:string,n:int}|null  $size
     * @param array<string,string[]>       $typedHeader canonical header name → required substrings
     */
    public function __construct(
        public string $id,
        public string $severity,
        public array $tags,
        public string $name,
        public string $product,
        public ?int $status,
        public array $bodyWords,
        public array $headerWords,
        public array $forbidden,
        public array $headerForbidden,
        public array $regexWitness,
        public ?array $size,
        public bool $wholeBodyExclusive,
        public array $typedHeader = []
    ) {
    }
}
