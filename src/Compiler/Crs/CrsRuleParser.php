<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler\Crs;

/**
 * Parses OWASP CoreRuleSet `.conf` files into CrsRule value objects.
 *
 * CRS is the interchange format here exactly as nuclei's authored YAML is for the other
 * pipeline: the generated `.conf` regex is consumed directly (CRS itself generates many of
 * them from a `regex-assembly` source with a Go toolchain — funnypot needs neither Go nor
 * that source, only the shipped `.conf`).
 *
 * Build-time only. This reads text; it never evaluates a CRS rule.
 */
final class CrsRuleParser
{
    /** attack-* tag -> funnypot attack class we hold a response archetype for. */
    private const CLASS_TAGS = [
        'attack-sqli' => 'sqli',
        'attack-xss' => 'xss',
        'attack-lfi' => 'lfi',
        'attack-rce' => 'rce',
    ];

    /**
     * Parse every `*.conf` (not `*.conf.example`) in a directory.
     *
     * @return CrsRule[]
     */
    public function parseDir(string $dir): array
    {
        $files = glob(rtrim($dir, '/') . '/*.conf') ?: [];
        sort($files);

        $rules = [];
        foreach ($files as $file) {
            foreach ($this->parseFile($file) as $rule) {
                $rules[] = $rule;
            }
        }

        return $rules;
    }

    /**
     * @return CrsRule[]
     */
    public function parseFile(string $file): array
    {
        $text = (string) file_get_contents($file);
        $base = basename($file);

        $rules = [];
        foreach ($this->logicalLines($text) as $line) {
            if (strncmp(ltrim($line), 'SecRule', 7) !== 0) {
                continue;
            }
            $rule = $this->parseSecRule($line, $base);
            if ($rule !== null) {
                $rules[] = $rule;
            }
        }

        return $rules;
    }

    /**
     * Join `\`-continued physical lines into one logical directive. Newlines inside the
     * joined buffer are flattened to spaces — a CRS operator argument is always on one
     * physical line, so only the top-level token structure is affected.
     *
     * @return string[]
     */
    private function logicalLines(string $text): array
    {
        $out = [];
        $buffer = '';
        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $line) {
            $right = rtrim($line);
            if ($right !== '' && substr($right, -1) === '\\') {
                $buffer .= substr($right, 0, -1) . ' ';
                continue;
            }
            $out[] = $buffer . $line;
            $buffer = '';
        }
        if ($buffer !== '') {
            $out[] = $buffer;
        }

        return $out;
    }

    private function parseSecRule(string $line, string $sourceFile): ?CrsRule
    {
        $line = ltrim($line);
        // Skip past "SecRule" + whitespace to the variable field.
        $rest = ltrim(substr($line, 7));

        // Variable field runs up to the first double-quoted string (the operator).
        $q = strpos($rest, '"');
        if ($q === false) {
            return null;
        }
        $varsField = rtrim(substr($rest, 0, $q));

        [$operatorRaw, $close] = $this->scanQuoted($rest, $q);

        // The actions are the next double-quoted string after the operator.
        $after = substr($rest, $close + 1);
        $q2 = strpos($after, '"');
        $actionsRaw = '';
        if ($q2 !== false) {
            [$actionsRaw] = $this->scanQuoted($after, $q2);
        }

        [$operator, $argument, $negated] = $this->splitOperator($operatorRaw);
        [$id, $severity, $tags, $paranoia] = $this->parseActions($actionsRaw);

        $attackClass = null;
        foreach ($tags as $tag) {
            if (isset(self::CLASS_TAGS[$tag])) {
                $attackClass = self::CLASS_TAGS[$tag];
                break;
            }
        }

        return new CrsRule(
            $id,
            $operator,
            $argument,
            $negated,
            $this->parseVariables($varsField),
            $tags,
            $severity,
            $paranoia,
            $attackClass,
            $sourceFile
        );
    }

    /**
     * Scan a double-quoted string starting at index $i (which points at the opening quote).
     * `\"` is an escaped quote (ModSecurity unescapes it before the operator sees it).
     *
     * @return array{0:string,1:int} [content, index of the closing quote]
     */
    private function scanQuoted(string $s, int $i): array
    {
        $out = '';
        $n = strlen($s);
        for ($j = $i + 1; $j < $n; $j++) {
            $c = $s[$j];
            if ($c === '\\' && $j + 1 < $n && $s[$j + 1] === '"') {
                $out .= '"';
                $j++;
                continue;
            }
            if ($c === '"') {
                return [$out, $j];
            }
            $out .= $c;
        }

        return [$out, $n];
    }

    /**
     * @return array{0:string,1:string,2:bool} [operator, argument, negated]
     */
    private function splitOperator(string $raw): array
    {
        $raw = ltrim($raw);
        $negated = false;
        if ($raw !== '' && $raw[0] === '!') {
            $negated = true;
            $raw = ltrim(substr($raw, 1));
        }
        if ($raw === '' || $raw[0] !== '@') {
            // No explicit operator ⇒ ModSecurity defaults to @rx.
            return ['rx', $raw, $negated];
        }
        $raw = substr($raw, 1);
        $sp = strpos($raw, ' ');
        if ($sp === false) {
            return [$raw, '', $negated];
        }

        return [substr($raw, 0, $sp), ltrim(substr($raw, $sp + 1)), $negated];
    }

    /**
     * @return string[] base variable names (selectors and count/negation modifiers stripped)
     */
    private function parseVariables(string $field): array
    {
        $field = trim($field);
        if ($field === '') {
            return [];
        }
        $vars = [];
        foreach (explode('|', $field) as $token) {
            $token = ltrim($token, "!&");
            $colon = strpos($token, ':');
            $vars[] = $colon === false ? $token : substr($token, 0, $colon);
        }

        return array_values(array_filter($vars, static function (string $v): bool {
            return $v !== '';
        }));
    }

    /**
     * Split the action list on top-level commas (a comma inside a 'single-quoted' value is
     * not a separator) and pull the fields funnypot uses. msg/logdata are deliberately never
     * captured — they are CRS's own audit vocabulary and must never reach a response body.
     *
     * @return array{0:string,1:string,2:string[],3:int|null} [id, severity, tags, paranoiaLevel]
     */
    private function parseActions(string $raw): array
    {
        $id = '';
        $severity = '';
        $tags = [];
        $paranoia = null;

        foreach ($this->splitTopLevel($raw) as $action) {
            $action = trim($action);
            if ($action === '') {
                continue;
            }
            $colon = strpos($action, ':');
            if ($colon === false) {
                continue;
            }
            $key = substr($action, 0, $colon);
            $value = trim(substr($action, $colon + 1));
            if (strlen($value) >= 2 && $value[0] === "'" && substr($value, -1) === "'") {
                $value = substr($value, 1, -1);
            }
            switch ($key) {
                case 'id':
                    $id = $value;
                    break;
                case 'severity':
                    $severity = $value;
                    break;
                case 'tag':
                    $tags[] = $value;
                    if (preg_match('#^paranoia-level/(\d+)$#', $value, $m) === 1) {
                        $paranoia = (int) $m[1];
                    }
                    break;
            }
        }

        return [$id, $severity, $tags, $paranoia];
    }

    /**
     * @return string[]
     */
    private function splitTopLevel(string $raw): array
    {
        $parts = [];
        $current = '';
        $inQuote = false;
        $n = strlen($raw);
        for ($i = 0; $i < $n; $i++) {
            $c = $raw[$i];
            if ($c === "'") {
                $inQuote = !$inQuote;
                $current .= $c;
                continue;
            }
            if ($c === ',' && !$inQuote) {
                $parts[] = $current;
                $current = '';
                continue;
            }
            $current .= $c;
        }
        if ($current !== '') {
            $parts[] = $current;
        }

        return $parts;
    }
}
