<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler\Crs;

/**
 * One parsed CRS `SecRule` directive, reduced to the fields funnypot cares about.
 *
 * CRS's own execution model (anomaly scoring across many rules, then a blocking
 * evaluation) is discarded — a honeypot wants any plausible attack-class signal, so a
 * single fired rule is a meaningful detection on its own. Only the detection SURFACE is
 * kept: the operator + its argument, the attack class, and the paranoia/severity buckets
 * used to gate the import. `msg`/`logdata` are never captured — they are CRS's own audit
 * vocabulary and must never reach a served response body.
 */
final class CrsRule
{
    /**
     * @param string      $id           CRS rule id, e.g. "942140"
     * @param string      $operator     operator name without the leading @, e.g. "rx", "pmFromFile", "detectSQLi"
     * @param string      $argument     the operator argument (regex text, or a .data filename)
     * @param bool        $negated      the operator was written "!@..." (a NOT match)
     * @param string[]    $variables    the target variables, e.g. ["ARGS", "REQUEST_COOKIES"]
     * @param string[]    $tags         every tag: value, verbatim
     * @param string      $severity     CRS severity token, e.g. "CRITICAL" (empty when absent)
     * @param int|null    $paranoiaLevel from tag "paranoia-level/N"; null when the rule carries no PL tag
     * @param string|null $attackClass  funnypot attack class derived from an attack-* tag we archetype, else null
     * @param string      $sourceFile   basename of the .conf the rule came from
     */
    /** @var string CRS rule id, e.g. "942140" */
    public $id;

    /** @var string operator name without the leading @, e.g. "rx", "pmFromFile", "detectSQLi" */
    public $operator;

    /** @var string the operator argument (regex text, or a .data filename) */
    public $argument;

    /** @var bool the operator was written "!@..." (a NOT match) */
    public $negated;

    /** @var string[] the target variables, e.g. ["ARGS", "REQUEST_COOKIES"] */
    public $variables;

    /** @var string[] every tag: value, verbatim */
    public $tags;

    /** @var string CRS severity token, e.g. "CRITICAL" (empty when absent) */
    public $severity;

    /** @var int|null from tag "paranoia-level/N"; null when the rule carries no PL tag */
    public $paranoiaLevel;

    /** @var string|null funnypot attack class derived from an attack-* tag we archetype, else null */
    public $attackClass;

    /** @var string basename of the .conf the rule came from */
    public $sourceFile;

    public function __construct(
        string $id,
        string $operator,
        string $argument,
        bool $negated,
        array $variables,
        array $tags,
        string $severity,
        ?int $paranoiaLevel,
        ?string $attackClass,
        string $sourceFile
    ) {
        $this->id = $id;
        $this->operator = $operator;
        $this->argument = $argument;
        $this->negated = $negated;
        $this->variables = $variables;
        $this->tags = $tags;
        $this->severity = $severity;
        $this->paranoiaLevel = $paranoiaLevel;
        $this->attackClass = $attackClass;
        $this->sourceFile = $sourceFile;
    }

    /** True when every target variable is a response-side surface funnypot never sees. */
    public function isResponseSide(): bool
    {
        if ($this->variables === []) {
            return false;
        }
        foreach ($this->variables as $var) {
            if (strncmp($var, 'RESPONSE_', 9) !== 0 && strncmp($var, 'FILES_TMP', 9) !== 0) {
                return false;
            }
        }

        return true;
    }
}
