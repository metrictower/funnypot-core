<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Crs;

use Funnypot\Support\Severity;

/**
 * Turns a CoreRuleSet `rules/` directory into funnypot attack templates — one broadened
 * template per attack class, reusing that class's existing response archetype.
 *
 * Portability filter (the CRS analog of the nuclei pipeline's Gate A/B skip audit): keep only
 * non-negated `@rx` and `@pmFromFile` rules, at or below the paranoia-level ceiling, tagged
 * for a class funnypot holds an archetype for. Everything else — opaque libinjection operators
 * (`@detectSQLi`/`@detectXSS`), higher paranoia levels, response-side rules, anomaly-only
 * bookkeeping, uncombinable backreference patterns — is dropped and recorded, never guessed at.
 *
 * The output feeds TIER 2 (TemplateAttackEmulator) only. It never touches the nuclei routing
 * corpus, so a byte-exact nuclei response always wins over this generic attack-class emulation.
 */
final class CrsCompiler
{
    /** Cap phrases pulled from one @pmFromFile dictionary, so the combined regex stays bounded. */
    private const MAX_PM_PHRASES = 200;

    /** Drop very short dictionary phrases — as unbounded substrings they over-match benign input. */
    private const MIN_PM_PHRASE_LEN = 4;

    /** Per-class combined-regex byte budget; keeps each alternation under PCRE's compile limit. */
    private const MAX_COMBINED_BYTES = 45000;

    private CrsRuleParser $parser;
    private CrsArchetypes $archetypes;
    private FingerprintGuard $guard;

    public function __construct(private string $rootDir)
    {
        $this->parser = new CrsRuleParser();
        $this->archetypes = new CrsArchetypes($rootDir);
        $this->guard = FingerprintGuard::fromPackage();
    }

    /**
     * @param int $maxParanoia PL ceiling (1 = CRS's own production-safe default)
     * @return array{templates:array<int,array<string,mixed>>,skipped:array<int,array<string,string>>,manifest:array<string,mixed>}
     */
    public function compile(string $rulesDir, int $maxParanoia = 1): array
    {
        $rules = $this->parser->parseDir($rulesDir);

        /**
         * Per class: ordered branch entries (higher-signal @rx first, @pmFromFile literals
         * last so they trim first under budget), the contributing rule ids, and the running
         * CRS-mapped severity.
         *
         * @var array<string,array{rx:array<int,array{branch:string,id:string}>,pm:array<int,array{branch:string,id:string}>,rules:string[],severity:string}> $classes
         */
        $classes = [];
        $skipped = [];

        foreach ($rules as $rule) {
            $reason = $this->skipReason($rule, $maxParanoia);
            if ($reason !== null) {
                if ($rule->id !== '') {
                    $skipped[] = ['id' => $rule->id, 'file' => $rule->sourceFile, 'reason' => $reason];
                }
                continue;
            }

            $class = (string) $rule->attackClass;
            $classes[$class] ??= ['rx' => [], 'pm' => [], 'rules' => [], 'severity' => 'low'];

            [$kind, $branches] = $this->branchesFor($rule, $rulesDir);
            if ($branches === []) {
                $skipped[] = ['id' => $rule->id, 'file' => $rule->sourceFile, 'reason' => $this->emptyReason($rule)];
                continue;
            }
            foreach ($branches as $branch) {
                $classes[$class][$kind][] = ['branch' => $branch, 'id' => $rule->id];
            }
            $classes[$class]['rules'][] = $rule->id;
            $classes[$class]['severity'] = Severity::ceiling(
                $classes[$class]['severity'],
                CrsSeverity::map($rule->severity)
            );
        }

        $templates = [];
        $classSummary = [];
        foreach (CrsArchetypes::classes() as $class) {
            if (!isset($classes[$class])) {
                continue;
            }
            $built = $this->buildTemplate($class, $classes[$class], $maxParanoia, $skipped);
            if ($built === null) {
                continue;
            }
            [$template, $summary] = $built;
            $templates[] = $template;
            $classSummary[$class] = $summary;
        }

        $kept = 0;
        foreach ($classSummary as $s) {
            $kept += $s['rules'];
        }

        return [
            'templates' => $templates,
            'skipped' => $skipped,
            'manifest' => [
                'source' => 'coreruleset',
                'paranoia_level_max' => $maxParanoia,
                'rules_kept' => $kept,
                'rules_skipped' => count($skipped),
                'classes' => $classSummary,
            ],
        ];
    }

    /** Non-null ⇒ the rule is not importable; the string is the audit reason. */
    private function skipReason(CrsRule $rule, int $maxParanoia): ?string
    {
        if ($rule->negated) {
            return 'negated-operator';
        }
        if ($rule->operator !== 'rx' && $rule->operator !== 'pmFromFile') {
            return 'opaque-operator:@' . $rule->operator;
        }
        if ($rule->attackClass === null) {
            return 'no-funnypot-archetype-for-class';
        }
        if ($rule->paranoiaLevel !== null && $rule->paranoiaLevel > $maxParanoia) {
            return 'paranoia-level/' . $rule->paranoiaLevel;
        }
        if ($rule->isResponseSide()) {
            return 'response-side-variable';
        }

        return null;
    }

    /**
     * The combinable branches this rule contributes. @rx yields one branch (or none if it
     * carries an uncombinable backreference / won't compile); @pmFromFile yields one escaped
     * literal per dictionary phrase (bounded).
     *
     * @return array{0:'rx'|'pm',1:string[]}
     */
    private function branchesFor(CrsRule $rule, string $rulesDir): array
    {
        $aggregator = new RegexAggregator();

        if ($rule->operator === 'rx') {
            $branch = $aggregator->prepare($rule->argument);

            return ['rx', $branch === null ? [] : [$branch]];
        }

        // @pmFromFile <file>.data — one phrase per non-comment line, bounded + length-filtered.
        $path = rtrim($rulesDir, '/') . '/' . basename($rule->argument);
        if (!is_file($path)) {
            return ['pm', []];
        }
        $branches = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $phrase = trim($line);
            if ($phrase === '' || $phrase[0] === '#' || strlen($phrase) < self::MIN_PM_PHRASE_LEN) {
                continue;
            }
            $branches[] = $aggregator->literal($phrase);
            if (count($branches) >= self::MAX_PM_PHRASES) {
                break;
            }
        }

        return ['pm', $branches];
    }

    private function emptyReason(CrsRule $rule): string
    {
        if ($rule->operator === 'rx') {
            return 'uncombinable-regex-backreference-or-invalid';
        }

        return 'pmfromfile-dictionary-missing-or-empty';
    }

    /**
     * @param array{rx:array<int,array{branch:string,id:string}>,pm:array<int,array{branch:string,id:string}>,rules:string[],severity:string} $data
     * @param array<int,array<string,string>> $skipped by-reference audit sink
     * @return array{0:array<string,mixed>,1:array<string,int>}|null [template, summary] or null when nothing compiled
     */
    private function buildTemplate(string $class, array $data, int $maxParanoia, array &$skipped): ?array
    {
        // @rx first (higher signal, keep-first), then @pmFromFile literals (trim-first).
        $ordered = array_merge($data['rx'], $data['pm']);
        $result = (new RegexAggregator())->build(
            array_map(static fn (array $e): string => $e['branch'], $ordered),
            self::MAX_COMBINED_BYTES
        );
        if ($result['regex'] === null) {
            return null;
        }

        // Anything trimmed to fit the budget/compile limit is audited: a dropped @rx branch is
        // a lost rule; dropped @pmFromFile literals are counted (many phrases share one rule id).
        $pmDropped = 0;
        for ($i = $result['included']; $i < count($ordered); $i++) {
            $entry = $ordered[$i];
            if ($i < count($data['rx'])) {
                $skipped[] = ['id' => $entry['id'], 'file' => 'coreruleset', 'reason' => 'combined-regex-budget'];
            } else {
                $pmDropped++;
            }
        }

        $archetype = $this->archetypes->for($class);
        $severity = Severity::ceiling($archetype['severity'], $data['severity']);

        $this->guard->assertResponseClean(
            $archetype['response']['body'],
            $archetype['response']['headers'],
            "attack-crs-{$class}"
        );

        $template = [
            'id' => $archetype['id'],
            'severity' => $severity,
            'priority' => $archetype['priority'],
            'tags' => ['attack', $class, 'crs', 'crs-pl' . $maxParanoia],
            'match' => [
                ['in' => 'request', 'regex' => $result['regex']],
            ],
            'response' => $archetype['response'],
        ];
        if ($archetype['expect'] !== []) {
            $template['expect'] = $archetype['expect'];
        }

        $summary = [
            'rules' => count($data['rules']),
            'branches' => $result['included'],
            'pm_phrases_dropped' => $pmDropped,
        ];

        return [$template, $summary];
    }
}
