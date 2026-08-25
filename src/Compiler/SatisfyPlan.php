<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

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
    /** @var string */
    public $id;

    /** @var string */
    public $severity;

    /** @var string[] */
    public $tags;

    /** @var string */
    public $name;

    /** @var string */
    public $product;

    /** @var int|null */
    public $status;

    /** @var string[] */
    public $bodyWords;

    /** @var string[] */
    public $headerWords;

    /** @var string[] */
    public $forbidden;

    /** @var string[] */
    public $headerForbidden;

    /** @var string[] */
    public $regexWitness;

    /** @var array{op:string,n:int}|null */
    public $size;

    /** @var bool */
    public $wholeBodyExclusive;

    /** @var array<string,string[]> canonical header name → required substrings */
    public $typedHeader;

    public function __construct(
        string $id,
        string $severity,
        array $tags,
        string $name,
        string $product,
        ?int $status,
        array $bodyWords,
        array $headerWords,
        array $forbidden,
        array $headerForbidden,
        array $regexWitness,
        ?array $size,
        bool $wholeBodyExclusive,
        array $typedHeader = []
    ) {
        $this->id = $id;
        $this->severity = $severity;
        $this->tags = $tags;
        $this->name = $name;
        $this->product = $product;
        $this->status = $status;
        $this->bodyWords = $bodyWords;
        $this->headerWords = $headerWords;
        $this->forbidden = $forbidden;
        $this->headerForbidden = $headerForbidden;
        $this->regexWitness = $regexWitness;
        $this->size = $size;
        $this->wholeBodyExclusive = $wholeBodyExclusive;
        $this->typedHeader = $typedHeader;
    }
}
