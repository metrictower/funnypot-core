<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

/**
 * A bounded reader for a GraphQL document. It never executes anything and never throws: it tokenises the
 * text, parses operations and fragment definitions into plain node lists, and reports a failure as either a
 * syntax error from a closed vocabulary (only punctuators or <EOF> are ever named, never request bytes) or a
 * decline (anything it does not model).
 *
 * Nesting is tracked with an explicit stack and argument lists are skipped with a counter, so hostile input
 * cannot recurse. Columns count UTF-16 code units, as graphql-js does.
 *
 * A field node is ['kind' => 'field', 'alias' => ?string, 'name' => string, 'line' => int, 'column' => int,
 * 'children' => list<node>|null (null when it has no selection set), 'braceLine' => int, 'braceColumn' =>
 * int, 'directives' => bool, 'typeArg' => ?string (the string `name:` argument, read for `__type` only)].
 * Fragment spreads and inline fragments are ['kind' => 'spread'|'inline', 'line' => int, 'column' => int,
 * 'children' => list<node>|null].
 */
final class GraphQlSelection
{
    public const MAX_BYTES = 8192;

    /** The only syntax messages ever served; a punctuator is the only thing they name. */
    public const UNEXPECTED_EOF = 'Syntax Error: Unexpected <EOF>.';
    public const EXPECTED_NAME_EOF = 'Syntax Error: Expected Name, found <EOF>.';
    public const EXPECTED_NAME_PUNCTUATOR = 'Syntax Error: Expected Name, found "%s".';
    public const UNTERMINATED_STRING = 'Syntax Error: Unterminated string.';

    private const PUNCTUATORS = '!$&()[]{}:=@|';
    private const NAME_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';

    /** @var string|null null on success, 'syntax' for a closed-vocabulary syntax error, 'decline' otherwise */
    public $failure;

    /** @var string the syntax error message when $failure is 'syntax' */
    public $message = '';

    /** @var int */
    public $line = 1;

    /** @var int */
    public $column = 1;

    /** @var list<array{type:string,name:?string,line:int,column:int,directives:bool,selection:list<array<string,mixed>>}> */
    public $operations = [];

    /** @var array<string,list<array<string,mixed>>> fragment name => selection */
    public $fragments = [];

    /** @var list<array{0:string,1:string,2:int,3:int}> kind, value, line, column */
    private $tokens = [];

    /** @var int */
    private $at = 0;

    private function __construct()
    {
    }

    public static function parse(string $source): self
    {
        $doc = new self();
        if (strlen($source) > self::MAX_BYTES) {
            $doc->failure = 'decline';

            return $doc;
        }
        if ($doc->lex($source)) {
            $doc->parseDocument();
        }

        return $doc;
    }

    /** UTF-16 code units in a UTF-8 string, without needing mbstring. */
    public static function utf16Units(string $s): int
    {
        if ($s === '' || preg_match('/[\x80-\xFF]/', $s) !== 1) {
            return strlen($s);
        }
        $continuation = preg_match_all('/[\x80-\xBF]/', $s);
        $fourByte = preg_match_all('/[\xF0-\xF7]/', $s);

        return strlen($s) - (int) $continuation + (int) $fourByte;
    }

    // --- lexer -------------------------------------------------------------------------------------

    private function lex(string $src): bool
    {
        $len = strlen($src);
        $pos = 0;
        $line = 1;
        $lineStart = 0;

        while (true) {
            while ($pos < $len) {
                $c = $src[$pos];
                if ($c === ' ' || $c === "\t" || $c === ',') {
                    $pos++;
                } elseif ($c === "\n") {
                    $pos++;
                    $line++;
                    $lineStart = $pos;
                } elseif ($c === "\r") {
                    $pos++;
                    if ($pos < $len && $src[$pos] === "\n") {
                        $pos++;
                    }
                    $line++;
                    $lineStart = $pos;
                } elseif ($c === '#') {
                    while ($pos < $len && $src[$pos] !== "\n" && $src[$pos] !== "\r") {
                        $pos++;
                    }
                } elseif ($c === "\xEF" && substr($src, $pos, 3) === "\xEF\xBB\xBF") {
                    $pos += 3;
                    if ($lineStart === $pos - 3) {
                        $lineStart = $pos;
                    }
                } else {
                    break;
                }
            }

            $column = 1 + self::utf16Units(substr($src, $lineStart, $pos - $lineStart));
            if ($pos >= $len) {
                $this->tokens[] = ['eof', '', $line, $column];

                return true;
            }

            $c = $src[$pos];
            if (strpos(self::PUNCTUATORS, $c) !== false) {
                $this->tokens[] = ['punct', $c, $line, $column];
                $pos++;
                continue;
            }
            if ($c === '.') {
                if (substr($src, $pos, 3) !== '...') {
                    return $this->decline();
                }
                $this->tokens[] = ['punct', '...', $line, $column];
                $pos += 3;
                continue;
            }
            // Byte ranges, not ctype_*: those follow the process locale and can accept non-ASCII bytes.
            if ($c === '_' || ($c >= 'a' && $c <= 'z') || ($c >= 'A' && $c <= 'Z')) {
                $n = strspn($src, self::NAME_CHARS, $pos);
                $this->tokens[] = ['name', substr($src, $pos, $n), $line, $column];
                $pos += $n;
                continue;
            }
            if ($c === '-' || ($c >= '0' && $c <= '9')) {
                if (preg_match('/\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/', $src, $m, 0, $pos) !== 1) {
                    return $this->decline();
                }
                $end = $pos + strlen($m[0]);
                if ($end < $len && ($src[$end] === '.' || strpos(self::NAME_CHARS, $src[$end]) !== false)) {
                    return $this->decline();
                }
                $this->tokens[] = ['number', $m[0], $line, $column];
                $pos = $end;
                continue;
            }
            if ($c === '"') {
                if (substr($src, $pos, 3) === '"""') {
                    $startLine = $line;
                    $i = $pos + 3;
                    $closed = false;
                    while ($i < $len) {
                        if ($src[$i] === '\\' && substr($src, $i, 4) === '\\"""') {
                            $i += 4;
                            continue;
                        }
                        if ($src[$i] === '"' && substr($src, $i, 3) === '"""') {
                            $closed = true;
                            $i += 3;
                            break;
                        }
                        if ($src[$i] === "\n" || ($src[$i] === "\r" && ($i + 1 >= $len || $src[$i + 1] !== "\n"))) {
                            $line++;
                            $lineStart = $i + 1;
                        }
                        $i++;
                    }
                    if (!$closed) {
                        return $this->syntaxAtEnd($src, $line, $lineStart, self::UNTERMINATED_STRING);
                    }
                    $this->tokens[] = ['string', '', $startLine, $column];
                    $pos = $i;
                    continue;
                }

                $i = $pos + 1;
                $value = '';
                while (true) {
                    if ($i >= $len) {
                        return $this->syntaxAtEnd($src, $line, $lineStart, self::UNTERMINATED_STRING);
                    }
                    $ch = $src[$i];
                    if ($ch === "\n" || $ch === "\r") {
                        return $this->syntax(self::UNTERMINATED_STRING, $line, 1 + self::utf16Units(substr($src, $lineStart, $i - $lineStart)));
                    }
                    if ($ch === '"') {
                        $i++;
                        break;
                    }
                    if ($ch === '\\') {
                        $esc = $i + 1 < $len ? $src[$i + 1] : '';
                        $map = ['"' => '"', '\\' => '\\', '/' => '/', 'b' => "\x08", 'f' => "\f", 'n' => "\n", 'r' => "\r", 't' => "\t"];
                        if (isset($map[$esc])) {
                            $value .= $map[$esc];
                            $i += 2;
                            continue;
                        }
                        if ($esc === 'u' && preg_match('/\G[0-9A-Fa-f]{4}/', $src, $hex, 0, $i + 2) === 1) {
                            $code = (int) hexdec($hex[0]);
                            $value .= $code < 0x80 ? chr($code) : '?';
                            $i += 6;
                            continue;
                        }

                        return $this->decline();
                    }
                    $value .= $ch;
                    $i++;
                }
                $this->tokens[] = ['string', $value, $line, $column];
                $pos = $i;
                continue;
            }

            return $this->decline();
        }
    }

    // --- parser ------------------------------------------------------------------------------------

    private function parseDocument(): void
    {
        if ($this->peek()[0] === 'eof') {
            $this->syntaxAt(self::UNEXPECTED_EOF, $this->peek());

            return;
        }

        while ($this->failure === null && $this->peek()[0] !== 'eof') {
            $t = $this->peek();
            if ($t[0] === 'punct' && $t[1] === '{') {
                $selection = $this->parseSelectionSet();
                if ($selection === null) {
                    return;
                }
                $this->operations[] = ['type' => 'query', 'name' => null, 'line' => $t[2], 'column' => $t[3], 'directives' => false, 'selection' => $selection];
                continue;
            }
            if ($t[0] === 'name' && ($t[1] === 'query' || $t[1] === 'mutation' || $t[1] === 'subscription')) {
                $this->at++;
                $name = null;
                if ($this->peek()[0] === 'name') {
                    $name = $this->next()[1];
                }
                if ($this->isPunct('(') && !$this->skipBalanced()) {
                    return;
                }
                $directives = $this->skipDirectives();
                if ($directives === null) {
                    return;
                }
                if (!$this->isPunct('{')) {
                    $this->decline();

                    return;
                }
                $selection = $this->parseSelectionSet();
                if ($selection === null) {
                    return;
                }
                $this->operations[] = ['type' => $t[1], 'name' => $name, 'line' => $t[2], 'column' => $t[3], 'directives' => $directives, 'selection' => $selection];
                continue;
            }
            if ($t[0] === 'name' && $t[1] === 'fragment') {
                $this->at++;
                $fragment = $this->expectName();
                if ($fragment === null) {
                    return;
                }
                $on = $this->next();
                if ($on[0] !== 'name' || $on[1] !== 'on') {
                    $this->decline();

                    return;
                }
                if ($this->expectName() === null || $this->skipDirectives() === null) {
                    return;
                }
                if (!$this->isPunct('{')) {
                    $this->decline();

                    return;
                }
                $selection = $this->parseSelectionSet();
                if ($selection === null) {
                    return;
                }
                $this->fragments[$fragment] = $selection;
                continue;
            }

            $this->decline();

            return;
        }
    }

    /**
     * Parse the selection set at the current `{` into nested node lists, without recursion.
     *
     * @return list<array<string,mixed>>|null
     */
    private function parseSelectionSet(): ?array
    {
        $this->at++; // the opening brace
        // Each frame: [nodes collected so far, the node that owns this set (null for the root), its count].
        $stack = [[[], null]];

        while (true) {
            $t = $this->peek();
            if ($t[0] === 'eof') {
                $this->syntaxAt(self::EXPECTED_NAME_EOF, $t);

                return null;
            }

            $depth = count($stack) - 1;
            if ($t[0] === 'punct' && $t[1] === '}') {
                if ($stack[$depth][0] === []) {
                    $this->syntaxAt(sprintf(self::EXPECTED_NAME_PUNCTUATOR, '}'), $t);

                    return null;
                }
                $this->at++;
                $frame = array_pop($stack);
                if ($stack === []) {
                    return $frame[0];
                }
                $owner = $frame[1];
                $owner['children'] = $frame[0];
                $stack[count($stack) - 1][0][] = $owner;
                continue;
            }

            if ($t[0] === 'punct' && $t[1] === '...') {
                $this->at++;
                $next = $this->peek();
                $node = ['kind' => 'spread', 'line' => $t[2], 'column' => $t[3], 'children' => null];
                if ($next[0] === 'name' && $next[1] !== 'on') {
                    $this->at++;
                    if ($this->skipDirectives() === null) {
                        return null;
                    }
                    $stack[$depth][0][] = $node;
                    continue;
                }
                if ($next[0] === 'name' && $next[1] === 'on') {
                    $this->at++;
                    if ($this->expectName() === null) {
                        return null;
                    }
                }
                if ($this->skipDirectives() === null) {
                    return null;
                }
                if (!$this->isPunct('{')) {
                    $this->decline();

                    return null;
                }
                $this->at++;
                $node['kind'] = 'inline';
                $stack[] = [[], $node];
                continue;
            }

            if ($t[0] === 'name') {
                $this->at++;
                $alias = null;
                $name = $t[1];
                if ($this->isPunct(':')) {
                    $this->at++;
                    $alias = $name;
                    $name = $this->expectName();
                    if ($name === null) {
                        return null;
                    }
                }
                $node = ['kind' => 'field', 'alias' => $alias, 'name' => $name, 'line' => $t[2], 'column' => $t[3],
                    'children' => null, 'braceLine' => 0, 'braceColumn' => 0, 'directives' => false, 'typeArg' => null];
                if ($this->isPunct('(')) {
                    if ($name === '__type') {
                        $node['typeArg'] = $this->peekTypeArgument();
                    }
                    if (!$this->skipBalanced()) {
                        return null;
                    }
                }
                $directives = $this->skipDirectives();
                if ($directives === null) {
                    return null;
                }
                $node['directives'] = $directives;
                if ($this->isPunct('{')) {
                    $brace = $this->next();
                    $node['braceLine'] = $brace[2];
                    $node['braceColumn'] = $brace[3];
                    $stack[] = [[], $node];
                    continue;
                }
                $stack[$depth][0][] = $node;
                continue;
            }

            if ($t[0] === 'punct') {
                $this->syntaxAt(sprintf(self::EXPECTED_NAME_PUNCTUATOR, $t[1]), $t);

                return null;
            }

            $this->decline();

            return null;
        }
    }

    /** The `name: "X"` string argument at the current `(`, without consuming anything. */
    private function peekTypeArgument(): ?string
    {
        $t = $this->tokens;
        $i = $this->at;
        if (($t[$i + 1][0] ?? '') === 'name' && $t[$i + 1][1] === 'name'
            && ($t[$i + 2][1] ?? '') === ':' && ($t[$i + 3][0] ?? '') === 'string'
            && ($t[$i + 4][1] ?? '') === ')') {
            return $t[$i + 3][1];
        }

        return null;
    }

    /** Skip a balanced `( … )` group at the current token. */
    private function skipBalanced(): bool
    {
        $this->at++;
        $depth = 1;
        while ($depth > 0) {
            $t = $this->next();
            if ($t[0] === 'eof') {
                $this->syntaxAt(self::UNEXPECTED_EOF, $t);

                return false;
            }
            if ($t[0] === 'punct' && $t[1] === '(') {
                $depth++;
            } elseif ($t[0] === 'punct' && $t[1] === ')') {
                $depth--;
            }
        }

        return true;
    }

    /** @return bool|null whether any directive was present; null on failure */
    private function skipDirectives(): ?bool
    {
        $any = false;
        while ($this->isPunct('@')) {
            $this->at++;
            if ($this->expectName() === null) {
                return null;
            }
            if ($this->isPunct('(') && !$this->skipBalanced()) {
                return null;
            }
            $any = true;
        }

        return $any;
    }

    private function expectName(): ?string
    {
        $t = $this->next();
        if ($t[0] === 'name') {
            return $t[1];
        }
        if ($t[0] === 'eof') {
            $this->syntaxAt(self::EXPECTED_NAME_EOF, $t);
        } elseif ($t[0] === 'punct') {
            $this->syntaxAt(sprintf(self::EXPECTED_NAME_PUNCTUATOR, $t[1]), $t);
        } else {
            $this->decline();
        }

        return null;
    }

    private function isPunct(string $p): bool
    {
        $t = $this->peek();

        return $t[0] === 'punct' && $t[1] === $p;
    }

    /** @return array{0:string,1:string,2:int,3:int} */
    private function peek(): array
    {
        return $this->tokens[$this->at] ?? $this->tokens[count($this->tokens) - 1];
    }

    /** @return array{0:string,1:string,2:int,3:int} */
    private function next(): array
    {
        $t = $this->peek();
        if ($t[0] !== 'eof') {
            $this->at++;
        }

        return $t;
    }

    private function decline(): bool
    {
        $this->failure = 'decline';

        return false;
    }

    private function syntax(string $message, int $line, int $column): bool
    {
        $this->failure = 'syntax';
        $this->message = $message;
        $this->line = $line;
        $this->column = $column;

        return false;
    }

    /** @param array{0:string,1:string,2:int,3:int} $t */
    private function syntaxAt(string $message, array $t): void
    {
        $this->syntax($message, $t[2], $t[3]);
    }

    private function syntaxAtEnd(string $src, int $line, int $lineStart, string $message): bool
    {
        return $this->syntax($message, $line, 1 + self::utf16Units(substr($src, $lineStart)));
    }
}
