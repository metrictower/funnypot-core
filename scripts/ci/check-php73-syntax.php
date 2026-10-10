<?php

declare(strict_types=1);

/**
 * Fail the build when runtime source uses syntax or functions newer than PHP 7.3.
 *
 * Core's floor is PHP 7.3 (WordPress hosts). A single 7.4+ construct in src/ is a ParseError on a
 * 7.3 host for every request that autoloads the file, yet the suite runs green on 8.x. This gate
 * tokenizes with the host PHP (8.1+; CI runs 8.3) and flags the newer constructs by token shape, so it runs
 * locally without a 7.3 binary. It is a guard, not a full 7.3 parser: the 7.3 leg of the test
 * matrix remains the authoritative check.
 *
 * Flagged: `??=`, arrow functions `fn`, `match`, nullsafe `?->`, `readonly`, `enum`, attributes
 * `#[`, typed or promoted properties, typed class constants, numeric literal separators, `0o`
 * octals, array unpacking `[...$a]`, union / intersection / `mixed` / `static` / `never` types and
 * trailing commas in signatures, `catch` without a variable, first-class callables `f(...)`,
 * `$obj::class`, and calls to functions added after 7.3 (str_contains etc.).
 * Not covered: named arguments, `throw` as an expression, `new` in initializers.
 *
 * Usage: php scripts/ci/check-php73-syntax.php [path ...]   (default: src bin)
 * Exit 0 clean, 1 on any violation.
 */

const POST_73_FUNCTIONS = [
    'str_contains', 'str_starts_with', 'str_ends_with', 'get_debug_type', 'get_resource_id',
    'array_is_list', 'fdiv', 'preg_last_error_msg', 'mb_str_split', 'enum_exists', 'array_find',
    'array_find_key', 'array_any', 'array_all', 'json_validate', 'mb_str_pad', 'str_increment',
    'str_decrement', 'get_mangled_object_vars', 'password_algos', 'mb_trim', 'mb_ltrim', 'mb_rtrim',
    'mb_ucfirst', 'mb_lcfirst',
];

const POST_73_TYPE_NAMES = ['mixed', 'never', 'static', 'null', 'false', 'true'];

/** @return list<string> */
function phpFiles(string $path): array
{
    if (is_file($path)) {
        return [$path];
    }
    if (!is_dir($path)) {
        return [];
    }
    $out = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        $name = $file->getPathname();
        if ($file->getExtension() === 'php' || ($file->getExtension() === '' && strpos((string) file_get_contents($name, false, null, 0, 64), '<?php') !== false)) {
            $out[] = $name;
        }
    }
    sort($out);
    return $out;
}

/** Significant tokens only (no whitespace/comments), each as [id, text, line]. */
function significantTokens(string $src): array
{
    $out = [];
    $line = 1;
    foreach (token_get_all($src) as $t) {
        if (is_array($t)) {
            $line = $t[2];
            if (in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML, T_OPEN_TAG, T_CLOSE_TAG], true)) {
                continue;
            }
            $out[] = [$t[0], $t[1], $t[2]];
        } else {
            $out[] = [$t, $t, $line];
        }
    }
    return $out;
}

function tokenIs(array $t, $id): bool
{
    return $t[0] === $id;
}

function isNameToken(array $t): bool
{
    $ids = [T_STRING, T_ARRAY, T_CALLABLE, T_STATIC];
    foreach (['T_NAME_QUALIFIED', 'T_NAME_FULLY_QUALIFIED', 'T_NAME_RELATIVE'] as $c) {
        if (defined($c)) {
            $ids[] = constant($c);
        }
    }
    return in_array($t[0], $ids, true);
}

/** True when a keyword token is used as a member/method/constant name, which 7.3 allows. */
function isMemberName(array $toks, int $i): bool
{
    $prev = $toks[$i - 1] ?? null;
    return $prev !== null && in_array($prev[0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_CONST], true);
}

/**
 * Scan a signature's type positions: params between the parens at $open, then an optional
 * closure `use (...)` and return type. Returns [violations, index after the signature].
 */
function scanSignature(array $toks, int $open): array
{
    $bad = [];
    $depth = 0;
    $inDefault = false;
    $n = count($toks);
    $i = $open;
    for (; $i < $n; $i++) {
        $t = $toks[$i];
        if ($t[0] === '(' || $t[0] === '[') {
            $depth++;
        } elseif ($t[0] === ']') {
            $depth--;
        } elseif ($t[0] === ')') {
            $depth--;
            if ($depth === 0) {
                break;
            }
        } elseif ($depth === 1 && $t[0] === ',') {
            $inDefault = false;
            if (isset($toks[$i + 1]) && $toks[$i + 1][0] === ')') {
                $bad[] = [$t[2], 'trailing comma in parameter list'];
            }
        } elseif ($depth === 1 && $t[0] === '=') {
            // A default value is an expression: `|` and `&` there are bitwise operators.
            $inDefault = true;
        } elseif ($depth === 1 && !$inDefault) {
            $next = $toks[$i + 1] ?? null;
            if ($t[0] === '|' && $next !== null && isNameToken($next)) {
                $bad[] = [$t[2], 'union type in parameter list'];
            } elseif ($t[1] === '&' && $next !== null && isNameToken($next)) {
                $bad[] = [$t[2], 'intersection type in parameter list'];
            } elseif (isNameToken($t) && $next !== null && (in_array($next[0], [T_VARIABLE, T_ELLIPSIS], true) || $next[1] === '&')
                && in_array(strtolower($t[1]), POST_73_TYPE_NAMES, true)) {
                $bad[] = [$t[2], "parameter type '{$t[1]}'"];
            } elseif (in_array($t[0], [T_PUBLIC, T_PROTECTED, T_PRIVATE], true)) {
                $bad[] = [$t[2], 'constructor property promotion'];
            }
        }
    }
    $i++;
    if (isset($toks[$i]) && $toks[$i][0] === T_USE) {
        $d = 0;
        for ($i++; $i < $n; $i++) {
            if ($toks[$i][0] === '(') {
                $d++;
            } elseif ($toks[$i][0] === ')' && --$d === 0) {
                $i++;
                break;
            }
        }
    }
    if (isset($toks[$i]) && $toks[$i][0] === ':') {
        for ($i++; $i < $n && !in_array($toks[$i][0], ['{', ';', T_DOUBLE_ARROW], true); $i++) {
            $t = $toks[$i];
            if ($t[0] === '|') {
                $bad[] = [$t[2], 'union return type'];
            } elseif ($t[1] === '&') {
                $bad[] = [$t[2], 'intersection return type'];
            } elseif (isNameToken($t) && in_array(strtolower($t[1]), POST_73_TYPE_NAMES, true)) {
                $bad[] = [$t[2], "return type '{$t[1]}'"];
            }
        }
    }
    return [$bad, $i];
}

/** @return list<array{int,string}> [line, reason] */
function scanFile(string $src): array
{
    $toks = significantTokens($src);
    $bad = [];
    $n = count($toks);
    $keywordTokens = [];
    foreach (['T_COALESCE_EQUAL' => '`??=` operator', 'T_FN' => 'arrow function `fn`', 'T_MATCH' => '`match` expression',
        'T_NULLSAFE_OBJECT_OPERATOR' => 'nullsafe `?->`', 'T_READONLY' => '`readonly`', 'T_ENUM' => '`enum`',
        'T_ATTRIBUTE' => 'attribute `#[`'] as $name => $reason) {
        if (defined($name)) {
            $keywordTokens[constant($name)] = $reason;
        }
    }

    // Open brackets; '[' or 'array(' marks an array literal, where `...` is 7.4 unpacking.
    $stack = [];
    for ($i = 0; $i < $n; $i++) {
        $t = $toks[$i];
        $prev = $toks[$i - 1] ?? null;
        $next = $toks[$i + 1] ?? null;

        if ($t[0] === '[') {
            $stack[] = 'array';
        } elseif ($t[0] === '(') {
            $stack[] = $prev !== null && in_array($prev[0], [T_ARRAY, T_LIST], true) ? 'array' : 'paren';
        } elseif ($t[0] === '{' || $t[0] === T_CURLY_OPEN || $t[0] === T_DOLLAR_OPEN_CURLY_BRACES) {
            $stack[] = 'brace';
        } elseif (in_array($t[0], [']', ')', '}'], true)) {
            array_pop($stack);
        } elseif ($t[0] === T_ELLIPSIS && end($stack) === 'array') {
            $bad[] = [$t[2], 'array unpacking `[...$a]`'];
            continue;
        }

        if ($t[0] === T_LNUMBER && preg_match('/^0[oO]/', $t[1])) {
            $bad[] = [$t[2], 'explicit octal `0o`'];
            continue;
        }

        if ($t[0] === T_CONST && $next !== null && isNameToken($next) && isset($toks[$i + 2]) && isNameToken($toks[$i + 2])) {
            $bad[] = [$t[2], 'typed class constant'];
            continue;
        }

        if (isset($keywordTokens[$t[0]]) && !isMemberName($toks, $i)) {
            $bad[] = [$t[2], $keywordTokens[$t[0]]];
            continue;
        }

        if (in_array($t[0], [T_LNUMBER, T_DNUMBER], true) && strpos($t[1], '_') !== false) {
            $bad[] = [$t[2], 'numeric literal separator'];
            continue;
        }

        // Skips promoted params (signature scan) and trait alias visibility (`f as protected`).
        if (in_array($t[0], [T_PUBLIC, T_PROTECTED, T_PRIVATE, T_VAR], true) && $prev !== null && !in_array($prev[0], ['(', ',', T_AS], true)) {
            $j = $i + 1;
            while (isset($toks[$j]) && in_array($toks[$j][0], [T_STATIC, T_ABSTRACT, T_FINAL], true)) {
                $j++;
            }
            if (isset($toks[$j]) && !in_array($toks[$j][0], [T_VARIABLE, T_FUNCTION, T_CONST], true)) {
                $bad[] = [$t[2], 'typed property'];
            }
            continue;
        }

        if ($t[0] === T_FUNCTION && !($prev !== null && $prev[0] === T_USE)) {
            $j = $i + 1;
            while (isset($toks[$j]) && $toks[$j][0] !== '(') {
                $j++;
            }
            if (isset($toks[$j])) {
                [$sigBad] = scanSignature($toks, $j);
                foreach ($sigBad as $b) {
                    $bad[] = $b;
                }
            }
            continue;
        }

        if ($t[0] === T_CATCH) {
            $j = $i + 1;
            $hasVar = false;
            for (; isset($toks[$j]) && $toks[$j][0] !== ')'; $j++) {
                if ($toks[$j][0] === T_VARIABLE) {
                    $hasVar = true;
                }
            }
            if (!$hasVar) {
                $bad[] = [$t[2], '`catch` without a variable'];
            }
            continue;
        }

        if ($t[0] === '(' && $next !== null && $next[0] === T_ELLIPSIS && isset($toks[$i + 2]) && $toks[$i + 2][0] === ')') {
            $bad[] = [$t[2], 'first-class callable `(...)`'];
            continue;
        }

        if ($t[0] === T_DOUBLE_COLON && $prev !== null && $prev[0] === T_VARIABLE && $next !== null && $next[0] === T_CLASS) {
            $bad[] = [$t[2], '`$object::class`'];
            continue;
        }

        if (isNameToken($t) && $next !== null && $next[0] === '(') {
            $fn = strtolower(ltrim($t[1], '\\'));
            if (in_array($fn, POST_73_FUNCTIONS, true)
                && !($prev !== null && in_array($prev[0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true))) {
                $bad[] = [$t[2], "function {$fn}() (PHP 7.4+)"];
            }
        }
    }
    return $bad;
}

$paths = array_slice($argv, 1);
if ($paths === []) {
    $root = dirname(__DIR__, 2);
    $paths = [$root . '/src', $root . '/bin'];
}

$violations = 0;
$scanned = 0;
foreach ($paths as $path) {
    foreach (phpFiles($path) as $file) {
        $scanned++;
        foreach (scanFile((string) file_get_contents($file)) as [$line, $reason]) {
            fwrite(STDERR, "{$file}:{$line}: {$reason} is not PHP 7.3-compatible\n");
            $violations++;
        }
    }
}

if ($scanned === 0) {
    fwrite(STDERR, "check-php73-syntax: no PHP files found\n");
    exit(1);
}
if ($violations > 0) {
    fwrite(STDERR, "check-php73-syntax: {$violations} violation(s) in {$scanned} file(s)\n");
    exit(1);
}
echo "check-php73-syntax: {$scanned} file(s) clean\n";
exit(0);
