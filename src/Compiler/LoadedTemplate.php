<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Normalized view of one nuclei template's FIRST http request, as consumed by the
 * compiler. Only the fields the inverter needs are lifted out of the raw YAML.
 *
 * Nuclei clusters (and we route) on a single request per template. `requestCount`
 * and the raw eligibility signals let Gate A reject multi-step / non-clusterable
 * templates before any matcher work.
 *
 * For a `raw:` template the method/path are lifted out of the first raw HTTP request
 * line (there is no separate `method`/`path` key). `rawRequestCount` is the number of
 * raw requests in the block; only a single-request raw block is invertible.
 */
final class LoadedTemplate
{
    /**
     * @param string[]              $tags
     * @param string[]              $paths            raw path strings incl. {{BaseURL}} prefix
     * @param array<int,mixed>      $matchers         raw matcher blocks (assoc arrays)
     * @param array<string,mixed>   $eligibilitySignals raw first-request keys used by Gate A
     *                                                 (raw/payloads/body/fuzzing/unsafe/name/req-condition)
     * @param int                   $rawRequestCount  raw HTTP requests in the block (0 when not raw)
     */
    /** @var string */
    public $id;

    /** @var string */
    public $severity;

    /** @var string[] */
    public $tags;

    /** @var string */
    public $product;

    /** @var string */
    public $name;

    /** @var string */
    public $method;

    /** @var string[] raw path strings incl. {{BaseURL}} prefix */
    public $paths;

    /** @var array<int,mixed> raw matcher blocks (assoc arrays) */
    public $matchers;

    /** @var string */
    public $matchersCondition;

    /** @var int */
    public $requestCount;

    /** @var bool */
    public $hasFlow;

    /** @var array<string,mixed> raw first-request keys used by Gate A (raw/payloads/body/fuzzing/unsafe/name/req-condition) */
    public $eligibilitySignals;

    /** @var string */
    public $rawText;

    /** @var int raw HTTP requests in the block (0 when not raw) */
    public $rawRequestCount;

    public function __construct(
        string $id,
        string $severity,
        array $tags,
        string $product,
        string $name,
        string $method,
        array $paths,
        array $matchers,
        string $matchersCondition,
        int $requestCount,
        bool $hasFlow,
        array $eligibilitySignals,
        string $rawText,
        int $rawRequestCount = 0
    ) {
        $this->id = $id;
        $this->severity = $severity;
        $this->tags = $tags;
        $this->product = $product;
        $this->name = $name;
        $this->method = $method;
        $this->paths = $paths;
        $this->matchers = $matchers;
        $this->matchersCondition = $matchersCondition;
        $this->requestCount = $requestCount;
        $this->hasFlow = $hasFlow;
        $this->eligibilitySignals = $eligibilitySignals;
        $this->rawText = $rawText;
        $this->rawRequestCount = $rawRequestCount;
    }
}
