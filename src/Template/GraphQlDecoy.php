<?php

declare(strict_types=1);

namespace Funnypot\Core\Template;

use Funnypot\Core\Support\GraphQlSelection;

/**
 * Answers a parsed GraphQL document from a fixed synthetic dataset, the way a graphql-js / Apollo server
 * with open reads and protected writes would: the requested fields only, graphql-js validation messages,
 * mutations refused as unauthenticated. Nothing is executed. Every message text comes from the rule's
 * config, so the static gates scan it.
 *
 * A null answer means "decline": the caller serves the rule's base response.
 */
final class GraphQlDecoy
{
    public const MAX_DEPTH = 6;
    public const MAX_FIELDS = 64;
    public const MAX_NODES = 500;
    public const MAX_ROWS = 5;
    /** Error codes, as Apollo Server names them. */
    public const CODES = ['GRAPHQL_PARSE_FAILED', 'GRAPHQL_VALIDATION_FAILED', 'OPERATION_RESOLUTION_FAILURE', 'BAD_REQUEST', 'UNAUTHENTICATED'];
    private const NAME = '/\A[_A-Za-z][_0-9A-Za-z]{0,63}\z/';
    private const MAX_SUGGESTIONS = 5;
    private const MAX_ROOT_SPREADS = 16;

    /** @var array<string,mixed> */
    private $config;

    /** @var callable(string): string renders one leaf template for the current seed */
    private $render;

    /** @var array<string,mixed> the decoded introspection `__schema` object */
    private $schema;

    /** @var int */
    private $nodes = 0;

    /** @var int byte budget for introspection answers in one response */
    private $maxBytes;

    /** @var int|null encoded size of the `__schema` answer, computed on first use */
    private $schemaBytes;

    /**
     * @param array<string,mixed> $config   the compiled `graphql-select` config
     * @param array<string,mixed> $schema   the decoded introspection `__schema` object
     * @param int                 $maxBytes the largest body the caller may serve
     */
    public function __construct(array $config, array $schema, callable $render, int $maxBytes = 65536)
    {
        $this->config = $config;
        $this->schema = $schema;
        $this->render = $render;
        $this->maxBytes = $maxBytes;
    }

    /**
     * @param bool $echo whether attacker-chosen names may appear in error messages
     * @return array{status:int, body:array<string,mixed>, headers?:array<string,string>}|null
     */
    public function answer(GraphQlSelection $doc, ?string $operationName, bool $isGet, bool $echo): ?array
    {
        if ($doc->failure === 'decline') {
            return null;
        }
        if ($doc->failure === 'syntax') {
            return $this->error(400, $doc->message, 'GRAPHQL_PARSE_FAILED', $doc->line, $doc->column);
        }

        $op = $this->selectOperation($doc, $operationName, $echo);
        if (!is_array($op) || isset($op['status'])) {
            return $op;
        }
        if ($op['type'] === 'subscription' || $op['directives']) {
            return null;
        }
        $rootType = $op['type'] === 'mutation' ? (string) ($this->config['roots']['mutation'] ?? 'Mutation')
            : (string) ($this->config['roots']['query'] ?? 'Query');
        $selection = self::expandRoot($op['selection'], $doc->fragments);
        if ($selection === null) {
            return null;
        }

        $data = [];
        foreach ($selection as $node) {
            if ($node['alias'] !== null && preg_match(self::NAME, $node['alias']) !== 1) {
                return null;
            }
            if ($op['type'] === 'query' && ($node['name'] === '__schema' || $node['name'] === '__type')) {
                continue;
            }
            $data[] = $node;
        }

        // Depth first: it walks at most MAX_DEPTH + 1 levels, so every later walk is bounded by it.
        $deepest = null;
        foreach ($data as $node) {
            $deepest = $deepest ?? self::deeperThan($node, 0, self::MAX_DEPTH);
        }
        if ($deepest !== null) {
            $name = ($echo && $op['name'] !== null && preg_match(self::NAME, $op['name']) === 1) ? $op['name'] : '';

            return $this->error(400, $this->message('depth', ['name' => $name, 'max' => (string) self::MAX_DEPTH]),
                'GRAPHQL_VALIDATION_FAILED', $deepest['line'], $deepest['column']);
        }
        foreach ($data as $node) {
            if (!self::plain($node)) {
                return null;
            }
        }
        $fields = 0;
        foreach ($data as $node) {
            $fields += self::countFields($node);
        }
        if ($fields > self::MAX_FIELDS) {
            return null;
        }

        foreach ($selection as $node) {
            if (in_array($node, $data, true)) {
                $invalid = $this->validate($node, $rootType, $echo);
            } else {
                $invalid = $this->validateIntrospection($node);
            }
            if ($invalid !== null) {
                return $invalid;
            }
            if ($node['name'] === '__type' && $node['typeArg'] === null) {
                return null;
            }
        }
        if (!self::keysAreConsistent($selection, false) || !self::keysAreConsistent($data, true)) {
            return null;
        }

        return $op['type'] === 'mutation' ? $this->mutation($selection, $isGet) : $this->query($selection, $rootType);
    }

    /**
     * The root selection with fragment spreads and inline fragments replaced by their fields, one level
     * deep. Null declines: an unknown fragment, a spread inside a spread, or too many spreads.
     *
     * @param list<array<string,mixed>>                $selection
     * @param array<string,list<array<string,mixed>>> $fragments
     * @return list<array<string,mixed>>|null
     */
    private static function expandRoot(array $selection, array $fragments): ?array
    {
        $out = [];
        $spreads = 0;
        foreach ($selection as $node) {
            if ($node['kind'] === 'field') {
                $out[] = $node;
                continue;
            }
            if (++$spreads > self::MAX_ROOT_SPREADS) {
                return null;
            }
            $inner = $node['kind'] === 'inline' ? $node['children'] : ($fragments[(string) ($node['fragment'] ?? '')] ?? null);
            if (!is_array($inner)) {
                return null;
            }
            foreach ($inner as $child) {
                if ($child['kind'] !== 'field') {
                    return null;
                }
                $out[] = $child;
            }
        }

        return $out;
    }

    // --- operation selection -------------------------------------------------------------------------

    /** @return array<string,mixed>|null the operation, an error answer, or null to decline */
    private function selectOperation(GraphQlSelection $doc, ?string $operationName, bool $echo): ?array
    {
        if ($doc->operations === []) {
            return null;
        }
        if ($operationName !== null && $operationName !== '') {
            foreach ($doc->operations as $op) {
                if ($op['name'] === $operationName) {
                    return $op;
                }
            }
            if ($echo && preg_match(self::NAME, $operationName) === 1) {
                return $this->error(400, $this->message('unknown_operation', ['name' => $operationName]), 'OPERATION_RESOLUTION_FAILURE');
            }

            return null;
        }
        if (count($doc->operations) > 1) {
            return $this->error(400, $this->message('multiple_operations', []), 'OPERATION_RESOLUTION_FAILURE');
        }

        return $doc->operations[0];
    }

    // --- validation ----------------------------------------------------------------------------------

    /** @param array<string,mixed> $node */
    private static function plain(array $node): bool
    {
        if ($node['kind'] !== 'field' || $node['directives']
            || ($node['alias'] !== null && preg_match(self::NAME, $node['alias']) !== 1)) {
            return false;
        }
        foreach ((array) $node['children'] as $child) {
            if (!self::plain($child)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The first field nested deeper than $max (a root field is depth 0), or null.
     *
     * @param array<string,mixed> $node
     * @return array<string,mixed>|null
     */
    private static function deeperThan(array $node, int $depth, int $max): ?array
    {
        if ($depth > $max) {
            return $node;
        }
        foreach ((array) $node['children'] as $child) {
            $found = self::deeperThan($child, $depth + 1, $max);
            if ($found !== null) {
                return $found;
            }
        }

        return null;
    }

    /** @param array<string,mixed> $node */
    private static function countFields(array $node): int
    {
        $n = 1;
        foreach ((array) $node['children'] as $child) {
            $n += self::countFields($child);
        }

        return $n;
    }

    /**
     * Two fields answering to one response key must be the same field (otherwise graphql-js reports an
     * overlap, which this decoy does not model).
     *
     * @param list<array<string,mixed>> $selection
     * @param bool                      $deep also check nested selections (only for depth-bounded data fields)
     */
    private static function keysAreConsistent(array $selection, bool $deep): bool
    {
        $seen = [];
        foreach ($selection as $node) {
            if ($node['kind'] !== 'field') {
                continue;
            }
            $key = $node['alias'] ?? $node['name'];
            if (isset($seen[$key]) && $seen[$key] !== $node['name']) {
                return false;
            }
            $seen[$key] = $node['name'];
            if ($deep && is_array($node['children']) && !self::keysAreConsistent($node['children'], true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The first validation error under this field, in document order, or null when it is valid.
     *
     * @param array<string,mixed> $node
     * @return array{status:int, body:array<string,mixed>}|null
     */
    private function validate(array $node, string $parentType, bool $echo): ?array
    {
        $name = (string) $node['name'];
        if ($name === '__typename') {
            if ($node['children'] !== null) {
                return $this->error(400, $this->message('must_not_have_selection', ['field' => $name, 'type' => 'String!']),
                    'GRAPHQL_VALIDATION_FAILED', $node['braceLine'], $node['braceColumn']);
            }

            return null;
        }

        $fields = (array) ($this->config['types'][$parentType] ?? []);
        if (!array_key_exists($name, $fields)) {
            $suggestions = $this->suggestions($name, array_keys($fields));
            $message = $echo && preg_match(self::NAME, $name) === 1
                ? $this->message('cannot_query', ['name' => $name, 'type' => $parentType])
                : $this->message('cannot_query_anonymous', ['type' => $parentType]);
            if ($suggestions !== []) {
                $message .= $this->message('did_you_mean', ['list' => self::quotedList($suggestions)]);
            }

            return $this->error(400, $message, 'GRAPHQL_VALIDATION_FAILED', $node['line'], $node['column']);
        }

        $def = $fields[$name];
        if (is_array($def)) {
            $target = (string) ($def['object'] ?? $def['list'] ?? '');
            $declared = isset($def['list']) ? '[' . $target . ']' : $target;
            if ($node['children'] === null) {
                return $this->error(400, $this->message('must_have_subfields', ['field' => $name, 'type' => $declared]),
                    'GRAPHQL_VALIDATION_FAILED', $node['line'], $node['column']);
            }
            foreach ($node['children'] as $child) {
                $invalid = $this->validate($child, $target, $echo);
                if ($invalid !== null) {
                    return $invalid;
                }
            }

            return null;
        }

        if ($node['children'] !== null) {
            return $this->error(400, $this->message('must_not_have_selection', ['field' => $name, 'type' => (string) $def]),
                'GRAPHQL_VALIDATION_FAILED', $node['braceLine'], $node['braceColumn']);
        }

        return null;
    }

    /**
     * `__schema` and `__type` need a selection of subfields, as any object field does.
     *
     * @param array<string,mixed> $node
     * @return array{status:int, body:array<string,mixed>}|null
     */
    private function validateIntrospection(array $node): ?array
    {
        if ($node['children'] !== null) {
            return null;
        }
        $type = $node['name'] === '__schema' ? '__Schema!' : '__Type';

        return $this->error(400, $this->message('must_have_subfields', ['field' => (string) $node['name'], 'type' => $type]),
            'GRAPHQL_VALIDATION_FAILED', $node['line'], $node['column']);
    }

    // --- answers -------------------------------------------------------------------------------------

    /**
     * @param list<array<string,mixed>> $selection
     * @return array{status:int, body:array<string,mixed>}|null
     */
    private function query(array $selection, string $rootType): ?array
    {
        $data = [];
        $spent = 0;
        foreach ($selection as $node) {
            $key = (string) ($node['alias'] ?? $node['name']);
            if (array_key_exists($key, $data)) {
                continue;
            }
            if ($node['name'] === '__schema') {
                $data[$key] = $this->schema;
                $spent += $this->schemaBytes();
            } elseif ($node['name'] === '__type') {
                $data[$key] = $this->lookupType((string) $node['typeArg']);
                $spent += strlen((string) json_encode($data[$key]));
            } elseif ($node['name'] === '__typename') {
                $data[$key] = $rootType;
            } else {
                $def = $this->config['types'][$rootType][$node['name']];
                $value = $this->config['data'][$node['name']] ?? null;
                $data[$key] = $this->project($node, $def, $value);
            }
            // Aliased introspection repeats a large answer; past the budget the decoy declines rather than
            // build a body it could not serve.
            if ($this->nodes > self::MAX_NODES || $spent > $this->maxBytes) {
                return null;
            }
        }

        return ['status' => 200, 'body' => ['data' => $data === [] ? new \stdClass() : $data]];
    }

    private function schemaBytes(): int
    {
        if ($this->schemaBytes === null) {
            $this->schemaBytes = strlen((string) json_encode($this->schema, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        }

        return $this->schemaBytes;
    }

    /**
     * @param list<array<string,mixed>> $selection
     * @return array{status:int, body:array<string,mixed>, headers?:array<string,string>}
     */
    private function mutation(array $selection, bool $isGet): array
    {
        if ($isGet) {
            return [
                'status' => 405,
                'headers' => ['Allow' => 'POST'],
                'body' => ['errors' => [[
                    'message' => $this->message('get_mutation', []),
                    'extensions' => ['code' => 'BAD_REQUEST'],
                ]]],
            ];
        }

        $errors = [];
        $data = [];
        foreach ($selection as $node) {
            $key = (string) ($node['alias'] ?? $node['name']);
            if (array_key_exists($key, $data)) {
                continue;
            }
            if ($node['name'] === '__typename') {
                $data[$key] = (string) ($this->config['roots']['mutation'] ?? 'Mutation');
                continue;
            }
            $errors[] = [
                'message' => $this->message('unauthenticated', []),
                'locations' => [['line' => $node['line'], 'column' => $node['column']]],
                'path' => [$key],
                'extensions' => ['code' => 'UNAUTHENTICATED'],
            ];
            $data[$key] = null;
        }

        return ['status' => 200, 'body' => $errors === [] ? ['data' => $data] : ['errors' => $errors, 'data' => $data]];
    }

    /**
     * @param array<string,mixed>      $node
     * @param string|array<string,mixed> $def
     * @param mixed                    $value
     * @return mixed
     */
    private function project(array $node, $def, $value)
    {
        $this->nodes++;
        if (!is_array($def)) {
            return $this->leaf((string) $def, $value);
        }
        if ($value === null) {
            return null;
        }
        $type = (string) ($def['object'] ?? $def['list'] ?? '');
        if (isset($def['list'])) {
            $rows = [];
            foreach (array_slice(array_values((array) $value), 0, self::MAX_ROWS) as $row) {
                $rows[] = $this->projectObject($node['children'], $type, (array) $row);
            }

            return $rows;
        }

        return $this->projectObject($node['children'], $type, (array) $value);
    }

    /**
     * @param list<array<string,mixed>> $children
     * @param array<string,mixed>      $row
     * @return array<string,mixed>|\stdClass
     */
    private function projectObject(array $children, string $type, array $row)
    {
        $out = [];
        foreach ($children as $child) {
            $key = (string) ($child['alias'] ?? $child['name']);
            if (array_key_exists($key, $out)) {
                continue;
            }
            if ($child['name'] === '__typename') {
                $this->nodes++;
                $out[$key] = $type;
                continue;
            }
            $def = $this->config['types'][$type][$child['name']];
            $out[$key] = $this->project($child, $def, $row[$child['name']] ?? null);
        }

        return $out === [] ? new \stdClass() : $out;
    }

    /**
     * A scalar value typed as the schema declares it.
     *
     * @param mixed $value
     * @return mixed
     */
    private function leaf(string $type, $value)
    {
        if ($value === null) {
            return null;
        }
        $base = rtrim($type, '!');
        if ($base !== '' && $base[0] === '[') {
            $out = [];
            foreach ((array) $value as $item) {
                $out[] = ($this->render)((string) $item);
            }

            return $out;
        }
        if ($base === 'Boolean') {
            return (bool) $value;
        }
        $text = ($this->render)((string) $value);
        if ($base === 'Int') {
            return preg_match('/\A-?(?:0|[1-9][0-9]{0,8})\z/', $text) === 1 ? (int) $text : null;
        }

        return $text;
    }

    /** @return array<string,mixed>|null */
    private function lookupType(string $name)
    {
        foreach ((array) ($this->schema['types'] ?? []) as $type) {
            if (is_array($type) && ($type['name'] ?? null) === $name) {
                return $type;
            }
        }

        return null;
    }

    // --- messages ------------------------------------------------------------------------------------

    /** @param array<string,string> $values */
    private function message(string $key, array $values): string
    {
        $template = (string) ($this->config['messages'][$key] ?? '');
        foreach ($values as $name => $value) {
            $template = str_replace('%' . $name . '%', $value, $template);
        }

        return $template;
    }

    /** @return array{status:int, body:array<string,mixed>} */
    private function error(int $status, string $message, string $code, ?int $line = null, ?int $column = null): array
    {
        $error = ['message' => $message];
        if ($line !== null && $column !== null) {
            $error['locations'] = [['line' => $line, 'column' => $column]];
        }
        $error['extensions'] = ['code' => $code];

        return ['status' => $status, 'body' => ['errors' => [$error]]];
    }

    /** @param list<string> $names */
    private static function quotedList(array $names): string
    {
        $quoted = array_map(static function (string $n): string {
            return '"' . $n . '"';
        }, array_slice($names, 0, self::MAX_SUGGESTIONS));
        if (count($quoted) === 1) {
            return $quoted[0];
        }
        if (count($quoted) === 2) {
            return $quoted[0] . ' or ' . $quoted[1];
        }
        $last = array_pop($quoted);

        return implode(', ', $quoted) . ', or ' . $last;
    }

    /**
     * graphql-js `suggestionList`: options within an edit distance of floor(len * 0.4) + 1 (optimal string
     * alignment; a case-only difference counts as 1), nearest first, then in natural order.
     *
     * @param list<string> $options
     * @return list<string>
     */
    private function suggestions(string $input, array $options): array
    {
        $threshold = (int) floor(strlen($input) * 0.4) + 1;
        $distances = [];
        foreach ($options as $option) {
            $d = self::lexicalDistance($input, (string) $option, $threshold);
            if ($d !== null) {
                $distances[(string) $option] = $d;
            }
        }
        $names = array_keys($distances);
        usort($names, static function (string $a, string $b) use ($distances): int {
            $diff = $distances[$a] - $distances[$b];

            return $diff !== 0 ? $diff : strnatcmp($a, $b);
        });

        return $names;
    }

    private static function lexicalDistance(string $input, string $option, int $threshold): ?int
    {
        if ($input === $option) {
            return 0;
        }
        $a = strtolower($option);
        $b = strtolower($input);
        if ($a === $b) {
            return 1;
        }
        if (strlen($a) < strlen($b)) {
            $t = $a;
            $a = $b;
            $b = $t;
        }
        $aLen = strlen($a);
        $bLen = strlen($b);
        if ($aLen - $bLen > $threshold) {
            return null;
        }

        $rows = [range(0, $bLen), array_fill(0, $bLen + 1, 0), array_fill(0, $bLen + 1, 0)];
        for ($i = 1; $i <= $aLen; $i++) {
            $up = $rows[($i - 1) % 3];
            $current = $rows[$i % 3];
            $current[0] = $i;
            $smallest = $i;
            for ($j = 1; $j <= $bLen; $j++) {
                $cost = $a[$i - 1] === $b[$j - 1] ? 0 : 1;
                $cell = min($up[$j] + 1, $current[$j - 1] + 1, $up[$j - 1] + $cost);
                if ($i > 1 && $j > 1 && $a[$i - 1] === $b[$j - 2] && $a[$i - 2] === $b[$j - 1]) {
                    $cell = min($cell, $rows[($i - 2) % 3][$j - 2] + 1);
                }
                if ($cell < $smallest) {
                    $smallest = $cell;
                }
                $current[$j] = $cell;
            }
            $rows[$i % 3] = $current;
            if ($smallest > $threshold) {
                return null;
            }
        }
        $distance = $rows[$aLen % 3][$bLen];

        return $distance <= $threshold ? $distance : null;
    }
}
