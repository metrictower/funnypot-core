<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

/**
 * Proves that a compiled artifact is inert DATA before it is ever `require`d.
 *
 * The compiled artifacts are loaded with `$x = require $path` (PhpArrayStore::fromFile,
 * TemplateAttackEmulator::fromFile, RouteTemplateSet::fromFile). If a fetched artifact
 * contained ANY executable PHP — a function call, an include/require/eval, an object
 * construction, a variable, a backtick — that code would run in the honeypot's web process
 * the instant the file is loaded. An ed25519 signature proves who produced the bytes; this
 * validator proves the bytes cannot execute, so a compromised signer still cannot ship code.
 *
 * A file passes iff it tokenises to exactly:
 *
 *     <?php  [declare(strict_types=1);]  return <array-literal> ;
 *
 * where <array-literal> is built only from array(...) / [...], the => arrow, single-quoted
 * strings, integer/float literals (optionally signed), and the bare constants
 * true / false / null. Whitespace and comments are allowed anywhere. Anything else — a
 * call, include, eval, a variable, a scope-resolution ::, new, a backtick, a second
 * statement, a close tag — is rejected. The check is a positive whitelist: an unknown
 * construct is a rejection, never a silent pass.
 */
final class PhpLiteralValidator
{
    /**
     * Hardest cap on a single artifact we will tokenise. The real index is ~6 MB; a
     * signed-but-absurdly-large artifact must not be able to OOM the host through this gate,
     * so anything past this is rejected without tokenising (a cheap DoS floor). Tokenising
     * scales ~50x in memory, so 64 MB source is already a heavy validation.
     */
    private const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;

    /** Token ids that carry no meaning for structure and may appear anywhere. */
    private const INSIGNIFICANT = [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT];

    /**
     * Token ids permitted inside the returned value, besides the array constructs, the
     * sign chars, and the true/false/null constants which are handled specially below.
     */
    private const VALUE_TOKENS = [
        T_DOUBLE_ARROW,
        T_CONSTANT_ENCAPSED_STRING,
        T_LNUMBER,
        T_DNUMBER,
    ];

    public function isValidFile(string $path): bool
    {
        $code = @file_get_contents($path);
        if ($code === false) {
            return false;
        }

        return $this->isValid($code);
    }

    public function isValid(string $code): bool
    {
        try {
            $this->validate($code);

            return true;
        } catch (PhpLiteralViolation $e) {
            return false;
        }
    }

    /** @throws PhpLiteralViolation when $code is not a pure return-array-literal file */
    public function validateFile(string $path, string $context = ''): void
    {
        $code = @file_get_contents($path);
        if ($code === false) {
            throw new PhpLiteralViolation('Cannot read artifact: ' . ($context !== '' ? $context : $path));
        }

        $this->validate($code, $context !== '' ? $context : $path);
    }

    /** @throws PhpLiteralViolation when $code is not a pure return-array-literal file */
    public function validate(string $code, string $context = 'artifact'): void
    {
        if (strpos($code, "\0") !== false) {
            $this->reject($context, 'contains a NUL byte');
        }
        if (strlen($code) > self::MAX_ARTIFACT_BYTES) {
            $this->reject($context, 'artifact exceeds the ' . self::MAX_ARTIFACT_BYTES . '-byte validation cap');
        }

        // Tokenising the real ~6 MB index peaks around 280 MB, so raise the ceiling for the
        // duration of this one bounded call and restore it afterward. Only ever raised, never
        // lowered; the MAX_ARTIFACT_BYTES cap above keeps the estimate finite. The token array
        // is freed before the limit is restored, so the restore can't fail against live usage.
        $restore = $this->raiseMemoryLimit(96 * 1024 * 1024 + strlen($code) * 64);
        $tokens = null;
        try {
            $this->validateTokens($code, $context);
        } finally {
            unset($tokens);
            if ($restore !== null) {
                @ini_set('memory_limit', $restore);
            }
        }
    }

    /** @throws PhpLiteralViolation */
    private function validateTokens(string $code, string $context): void
    {
        $tokens = @token_get_all($code);

        if (!is_array($tokens) || $tokens === []) {
            $this->reject($context, 'not tokenisable PHP');
        }

        $count = count($tokens);

        // 1. Must open with exactly <?php (T_OPEN_TAG). No short-echo tag, no leading HTML.
        if ($this->id($tokens[0]) !== T_OPEN_TAG) {
            $this->reject($context, 'does not begin with a plain <?php tag');
        }
        $i = 1;

        // 2. Optional declare(strict_types=1); header.
        $i = $this->skipInsignificant($tokens, $i, $count);
        if ($i < $count && $this->id($tokens[$i]) === T_DECLARE) {
            $i = $this->consumeDeclare($tokens, $i, $count, $context);
            $i = $this->skipInsignificant($tokens, $i, $count);
        }

        // 3. return.
        if ($i >= $count || $this->id($tokens[$i]) !== T_RETURN) {
            $this->reject($context, 'first statement is not a bare return');
        }
        $i++;

        // 4. The value: a balanced literal terminated by a top-level ;.
        $depth = 0;
        $prevSig = T_RETURN;
        $terminated = false;

        for (; $i < $count; $i++) {
            $id = $this->id($tokens[$i]);
            $text = $this->text($tokens[$i]);

            if ($id !== null && in_array($id, self::INSIGNIFICANT, true)) {
                continue;
            }

            if ($id === null) {
                $depth = $this->consumeChar($text, $prevSig, $depth, $terminated, $context);
                $prevSig = null;
                if ($terminated) {
                    break;
                }
                continue;
            }

            if ($id === T_ARRAY) {
                $prevSig = T_ARRAY;
                continue;
            }

            if (in_array($id, self::VALUE_TOKENS, true)) {
                $prevSig = $id;
                continue;
            }

            if ($id === T_STRING) {
                $lower = strtolower($text);
                if ($lower !== 'true' && $lower !== 'false' && $lower !== 'null') {
                    $this->reject($context, 'identifier ' . $text . ' (only true/false/null allowed)');
                }
                $prevSig = $id;
                continue;
            }

            $this->reject($context, 'disallowed token ' . token_name((int) $id));
        }

        if (!$terminated) {
            $this->reject($context, 'no top-level ; terminating the return');
        }

        // 5. After the terminating ;, only whitespace/comments — no second statement, no
        //    trailing close tag that could emit output.
        $i++;
        for (; $i < $count; $i++) {
            $id = $this->id($tokens[$i]);
            if ($id !== null && in_array($id, self::INSIGNIFICANT, true)) {
                continue;
            }
            $tok = $id === null ? $this->text($tokens[$i]) : token_name((int) $id);
            $this->reject($context, 'trailing content after the return statement (' . $tok . ')');
        }
    }

    /** Token id, or null for a single-character token. @param array|string $token */
    private function id($token): ?int
    {
        return is_array($token) ? $token[0] : null;
    }

    /** Token text. @param array|string $token */
    private function text($token): string
    {
        return is_array($token) ? $token[1] : $token;
    }

    /**
     * Raise memory_limit to at least $needBytes for the current call, returning the prior
     * value to restore (or null when no change was made — unlimited, or already high enough).
     */
    private function raiseMemoryLimit(int $needBytes): ?string
    {
        $current = ini_get('memory_limit');
        if ($current === false || $current === '' || $current === '-1') {
            return null;
        }
        $currentBytes = $this->bytesFromIni($current);
        if ($currentBytes >= $needBytes) {
            return null;
        }
        ini_set('memory_limit', (string) $needBytes);

        return $current;
    }

    private function bytesFromIni(string $value): int
    {
        $value = trim($value);
        $unit = strtolower(substr($value, -1));
        $num = (int) $value;
        switch ($unit) {
            case 'g':
                return $num * 1024 * 1024 * 1024;
            case 'm':
                return $num * 1024 * 1024;
            case 'k':
                return $num * 1024;
            default:
                return $num;
        }
    }

    /**
     * Validate one single-character token inside the value and return the new bracket depth.
     * Sets $terminated when a top-level ; is reached.
     */
    private function consumeChar(string $text, $prevSig, int $depth, bool &$terminated, string $context): int
    {
        switch ($text) {
            case '(':
                // A parenthesis is only ever the array( opener; anything else is a call.
                if ($prevSig !== T_ARRAY) {
                    $this->reject($context, 'parenthesis that is not an array() opener (possible call)');
                }

                return $depth + 1;
            case '[':
                return $depth + 1;
            case ')':
            case ']':
                if ($depth - 1 < 0) {
                    $this->reject($context, 'unbalanced closing bracket');
                }

                return $depth - 1;
            case ',':
            case '-':
            case '+':
                return $depth;
            case '.':
                // var_export() renders a binary string (e.g. the SQLite magic header) as
                // 'printable' . "\x00" . 'rest'. Concatenation is safe here: every operand
                // the whitelist admits is a compile-time constant (string/number/true/
                // false/null), and a call's '(' is still rejected, so '.' cannot smuggle a
                // side effect in.
                return $depth;
            case ';':
                if ($depth !== 0) {
                    $this->reject($context, 'semicolon inside the literal');
                }
                $terminated = true;

                return $depth;
            default:
                $this->reject($context, 'disallowed character token ' . $text);
        }

        return $depth;
    }

    /**
     * @param array<int,array{0:int,1:string,2:int}|string> $tokens
     */
    private function consumeDeclare(array $tokens, int $i, int $count, string $context): int
    {
        // Exactly: declare ( strict_types = <int> ) ;
        $i++;
        $i = $this->skipInsignificant($tokens, $i, $count);
        $this->expectChar($tokens, $i, $count, '(', $context);
        $i = $this->skipInsignificant($tokens, $i + 1, $count);
        if ($i >= $count || $this->id($tokens[$i]) !== T_STRING || strtolower($this->text($tokens[$i])) !== 'strict_types') {
            $this->reject($context, 'declare directive other than strict_types');
        }
        $i = $this->skipInsignificant($tokens, $i + 1, $count);
        $this->expectChar($tokens, $i, $count, '=', $context);
        $i = $this->skipInsignificant($tokens, $i + 1, $count);
        if ($i >= $count || $this->id($tokens[$i]) !== T_LNUMBER) {
            $this->reject($context, 'malformed declare value');
        }
        $i = $this->skipInsignificant($tokens, $i + 1, $count);
        $this->expectChar($tokens, $i, $count, ')', $context);
        $i = $this->skipInsignificant($tokens, $i + 1, $count);
        $this->expectChar($tokens, $i, $count, ';', $context);

        return $i + 1;
    }

    /**
     * @param array<int,array{0:int,1:string,2:int}|string> $tokens
     */
    private function expectChar(array $tokens, int $i, int $count, string $char, string $context): void
    {
        if ($i >= $count || $this->id($tokens[$i]) !== null || $this->text($tokens[$i]) !== $char) {
            $this->reject($context, 'malformed declare header');
        }
    }

    /**
     * @param array<int,array{0:int,1:string,2:int}|string> $tokens
     */
    private function skipInsignificant(array $tokens, int $i, int $count): int
    {
        while ($i < $count) {
            $id = $this->id($tokens[$i]);
            if ($id === null || !in_array($id, self::INSIGNIFICANT, true)) {
                break;
            }
            $i++;
        }

        return $i;
    }

    private function reject(string $context, string $why): void
    {
        throw new PhpLiteralViolation($context . ': ' . $why . '.');
    }
}
