<?php

declare(strict_types=1);

namespace Funnypot;

use Funnypot\Response\Style;

/**
 * The synthesize-only remainder of Config (two-phase design §3 / §7): the knobs that shape
 * WHAT a fake looks like and its safety bounds — never WHEN/whether to serve one (that left
 * core for the policy). Held by the engine; consulted only by synthesize().
 *
 * 7.3-clean: classic constructor, docblocked untyped properties (no promotion / typed props).
 */
final class SynthesisConfig
{
    /** @var string minimal | realistic | taunt (see Response\Style) */
    public $responseStyle;

    /** @var string refuse to fabricate anything stronger than this severity */
    public $severityCeiling;

    /** @var string[] template ids / pids / tags to never serve */
    public $exclude;

    /** @var bool false drops every nuclei-corpus fake (route + attack emulations still serve) */
    public $nucleiReflection;

    /** @var bool interactive attack-class emulation on a route miss */
    public $attackEmulation;

    /** @var int hard cap; a larger synthesized body is refused */
    public $maxBodyBytes;

    /** @var string|null Server banner for one coherent server identity; null ⇒ don't force one */
    public $serverHeader;

    /** @var string|null X-Powered-By, consistent with serverHeader; null ⇒ omit */
    public $poweredBy;

    /**
     * @param string[] $exclude
     */
    public function __construct(
        string $responseStyle = Style::MINIMAL,
        string $severityCeiling = 'high',
        array $exclude = [],
        bool $nucleiReflection = true,
        bool $attackEmulation = false,
        int $maxBodyBytes = 65536,
        ?string $serverHeader = null,
        ?string $poweredBy = null
    ) {
        $this->responseStyle = $responseStyle;
        $this->severityCeiling = $severityCeiling;
        $this->exclude = $exclude;
        $this->nucleiReflection = $nucleiReflection;
        $this->attackEmulation = $attackEmulation;
        $this->maxBodyBytes = $maxBodyBytes;
        $this->serverHeader = $serverHeader;
        $this->poweredBy = $poweredBy;
    }

    /** Carry the synthesize-only knobs across from a (legacy) Config. */
    public static function fromConfig(Config $config): self
    {
        return new self(
            $config->responseStyle,
            $config->severityCeiling,
            $config->exclude,
            $config->nucleiReflection,
            $config->attackEmulation,
            $config->maxBodyBytes,
            $config->serverHeader,
            $config->poweredBy
        );
    }
}
